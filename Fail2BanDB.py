import os
from datetime import datetime
from datetime import timedelta

import pytz
from django.core.wsgi import get_wsgi_application
from django.db import IntegrityError
from django.db.models import Q
from netaddr import IPNetwork, IPAddress, AddrFormatError


from .models import Event, Offenders, Ban_Events, Whitelist

blacklist_duration = 7  # in days
max_strikes = 3  # number of times something can get banned within the strike_gap until it's blacklisted
strike_gap = 3600
ban_user = 'Fail2BanDB'  # default system user for auto banning
ban_reason = 'Exceeded max_strikes within strike_gap; system autoban.'
unban_reason = 'Reached auto Unban time'


def get_whitelist_subnets():
    """
    gets all ip addresses in whitelist db with a subnet
    :return: list of subnet whitelist ip - subnet_list
    """
    subnet_list = []
    whitelist = Whitelist.objects.all()
    for entry in whitelist:
        if '/' in entry.ip:
            subnet_list.append(entry.ip)
    return subnet_list


def ip_in_range(ip, range):
    """
    checks if ip provided is in a range provided
    :param ip: ip to be checked
    :param range: range to be checked against
    :return: True if in range. False if not in range
    """
    if '/' not in range:
        range += '/32'
    # range is in IP/CIDR format eg 127.0.0.1/24
    if IPAddress(ip) in IPNetwork(range):
        return True
    else:
        return False


def check_ip(ip):
    """
    checks if ip is in range of the subnets in the whitelist
    :param ip: ip to be checked
    :return: returns FALSE if in range. Returns TRUE if not in range
    """
    subnets = get_whitelist_subnets()
    for subnet in subnets:
        if ip_in_range(ip, subnet):
            return False
    return True


def whitelist():
    """
    generates the whitelist
    :return: ip list
    """
    ips = Whitelist.objects.all()
    ip_list = []
    for entry in ips:
        ip_list.append(entry.ip)
    return ip_list


def create_event(ip, target_ip, time, protocol, port, hostname, name):
    """
    Function: create_event
    Purpose: Used for creating an event given individual params. Basically it just takes
    those params and shoves them into the dictionary that log_event is looking for
    :param ip:
    :param target_ip:
    :param time:
    :param protocol:
    :param port:
    :param hostname:
    :param name:
    :return: dictionary event_info
    """
    try:
        if not check_ip(ip):
            print "Didn't add offender since he is on the whitelist"
            check_ip(target_ip)
        else:
            event_info = {}
            event_info.update(
                {
                    'offender_ip': ip,
                    'target_ip': target_ip,
                    'time': datetime.utcnow().replace(tzinfo=pytz.utc),
                    'protocol': protocol,
                    'port': port,
                    'hostname': hostname,
                    'name': name,
                }
            )
            return log_event(event_info)
    except AddrFormatError:
        print "Not valid IP"


def log_event(event_info):
    """
    Function: log_event
    Purpose: Adds the event to the database connected to. After the event is added it calls 'add_offender'
    to add the offending IP address to the offenders list.
    :param event_info
        event_info['offender_ip'] = $ip;
        event_info['target_ip'] = $target_ip;
        event_info['time'] = $time;
        event_info['protocol'] = $protocol;
        event_info['port'] = $port;
        event_info['hostname'] = $hostname;
        event_info['name'] = $name;
    :return:
    """
    print event_info
    newEvent = Event(**event_info)
    newEvent.save()
    return add_offender(event_info['offender_ip'], event_info['time'], event_info['target_ip'])


def get_last_offense(ip_address):
    """
    Function: get_last_offense
    Purpose: Returns the most recent event for a given IP
    :param ip_address - The IP address you want to lookup the most recent ban event for.
    :return an array with the last offense data or 'IP not found'
    """
    event = Event.objects.filter(offender_ip=ip_address).values()
    if event:
        return event
    else:
        print 'IP not found'


def add_offender(ip_address, date, target, subnet=None, tags=None):
    """
    adds a new offender to db
    :param ip_address: ip address of offender
    :param date: date of offence
    :param target: target ip
    :return:
    """
    offender = Offenders.objects.filter(ip=ip_address)
    if offender:
        last_offence_date = offender[0].last_offense_date
        return update_offender(offender, ip_address, last_offence_date, date, target, subnet, tags)
    else:
        offender = Offenders(
            ip=ip_address,
            last_offense_date=date,
            last_offense_target=target,
        )
        if subnet:
            offender.subnet_mask = subnet
        if tags:
            offender.tag = tags

        try:
            offender.save()
            print "new offender %s" % ip_address
            return offender
        except IntegrityError:
            print "bad ip address %s or unknown error :*(" % ip_address
            return "Failed to add offender %s" % ip_address


def update_offender(offender, ip_address, last_offence_date, date, target, subnet=None, tags=None):
    """
    updates offender already in db
    :param offender: offender to be updated
    :param ip_address: ip address of affender
    :param last_offence_date: rlast offence of offender
    :param date: time now
    :param target: target ip
    :return:
    """
    strikes = update_strikes(ip_address, last_offence_date, date)
    offender = Offenders.objects.filter(ip=ip_address)
    # TODO: Too many update statements need to condense to one
    offender.update(
        ip=ip_address,
        last_offense_date=date,
        last_offense_target=target,
        total_strikes=offender[0].total_strikes + 1,
        strikes=strikes
    )
    if tags:
        offender.update(tag=tags)

    if subnet:
        offender.update(subnet_mask=subnet)
    check_ban_offender(ip_address, last_offence_date)
    print "updated offender %s" % ip_address
    return "Updated offender %s" % ip_address


def update_strikes(ip_address, last_offence_date, recent_offense_date):
    """
    updates strikes for offender
    :param ip_address: ip address of offender
    :param last_offence_date: last offence date of offender
    :param recent_offense_date: new offence date
    :return: new number of strikes != total strikes
    """
    time_delta = recent_offense_date.replace(tzinfo=pytz.utc) - last_offence_date.replace(tzinfo=pytz.utc)
    offender = Offenders.objects.filter(ip=ip_address)[0]
    strikes = offender.strikes
    if time_delta.total_seconds() < strike_gap:
        strikes = strikes + 1
    else:
        strikes = 1
    return strikes


def check_ban_offender(ip_address, recent_offence):
    """
    checks if offender needs to be banned {if total strikes % 3 = 0}
    :param ip_address: ip address of offender
    :param recent_offence: time
    :return:
    """
    offender = Offenders.objects.filter(ip=ip_address)[0]
    # if offender.blacklist_duration == 0:
    #     ban_offender(ip_address, ban_user, ban_reason, recent_offence, ban_option=False)
    if offender.total_strikes % 3 == 0:
        ban_offender(ip_address, ban_user, ban_reason, recent_offence, ban_option=True)


def ban_offender(ip_address, user, reason, time, ban_option, banDuration=None,
                 forceBan=None, subnet=None, tags=None):
    """
    bans offender and puts them on the blacklist
    :param ip_address: ip address of offender
    :param user: user who banned the offender
    :param reason: reason for ban
    :param time: time of ban
    :param ban_option: True = Ban, False = Un-Ban
    :param banDuration: -1  = perma-ban. Duration in days.
    :param forceBan: Used to ban a user regardless of strikes or anything else
    :return:
    """
    try:
        check_ip(ip_address)
    except AddrFormatError:
        print "Not valid IP"
        return "Failure: Not valid IP %s" % ip_address

    if not check_ip(ip_address):
        print "not banning because in whitelist"
        return "Failure: Not banning because %s is in whitelist" % ip_address
    elif forceBan:
        add_offender(ip_address, time, None, subnet, tags)
        return force_ban(ip_address, user, reason, time, True, banDuration)
    else:
        offender = Offenders.objects.get(ip=ip_address)

        if not offender:
            offender = create_event(ip_address,None,time,'tcp','ssh',None,'ssh')


        if offender:
            if isinstance(offender,list):
                print "Hey I got a list of offenders....wtf"
                offender = offender[0]
            #offender = offender[0]

            if not ban_option:
                Offenders.objects.filter(ip=ip_address).update(
                    blacklist_duration=0,
                    last_blacklist_remove_date=datetime.utcnow().replace(tzinfo=pytz.utc),
                    blacklisted=False,
                )
                log_ban_event(ip_address, reason, user, time, ban_option)
                print "offender removed from blacklist"
                return "Success: Offender %s removed from blacklist" % ip_address
            else:
                total_strikes = offender.total_strikes
                if total_strikes % 3 == 0:
                    ban_duration = (total_strikes / 3) * blacklist_duration
                    if ban_duration >= 90:
                        ban_duration = 90
                    Offenders.objects.filter(ip=ip_address).update(
                        blacklist_duration=ban_duration,
                        last_blacklisted_date=datetime.utcnow().replace(tzinfo=pytz.utc),
                        blacklisted=True,
                        strikes=1,
                        blacklist_removal_date=datetime.utcnow().replace(tzinfo=pytz.utc) + timedelta(days=ban_duration)
                    )
                    log_ban_event(ip_address, reason, user, time, ban_option)
                    print 'banned %s on %s' % (ip_address, datetime.utcnow().replace(tzinfo=pytz.utc))
                    return 'Success: Banned %s on %s' % (ip_address, datetime.utcnow().replace(tzinfo=pytz.utc))
                else:
                    print "ban stay same"
                    return "Info: No action; ban remains."
        else:
            print "not sure how we got here"
            return "Error: Unknown"


def force_ban(ip_address, user, reason, time, ban_option, banDuration):
    """
    bans a user regardles of strikes
    :param ip_address: offender ip address
    :param user: user thats is banning
    :param reason: reason for ban
    :param time: time of ban
    :param ban_option: ban or un-ban
    :param banDuration: ban duration
    :return:
    """
    if int(banDuration) == -1:
        banDuration = -1
        blacklist_removal_date = None
    else:
        blacklist_removal_date = datetime.utcnow().replace(tzinfo=pytz.utc) + timedelta(days=int(banDuration))
    Offenders.objects.filter(ip=ip_address).update(
        blacklist_duration=banDuration,
        last_blacklisted_date=datetime.utcnow().replace(tzinfo=pytz.utc),
        blacklisted=True,
        strikes=1,
        blacklist_removal_date=blacklist_removal_date
    )
    log_ban_event(ip_address, reason, user, time, ban_option)


def log_ban_event(ip_address, reason, user, time, action):
    """
    logs a ban event
    :param ip_address: ip address of attacker
    :param reason: reason for ban
    :param user: user of ban
    :param time: time of ban
    :param action: ban or unban
    :return:
    """
    event = Ban_Events(
        offender_ip=ip_address,
        reason=reason,
        user=user,
        date=time,
        action=int(action),
    )
    event.save()


def ban_offenders(ip_addresses, user, reason, ban_option):
    """
    bans multiple offenders through file upload (csv, txt)
    :param ip_addresses: file of ip addresses
    :param user: user of ban
    :param reason: reason of ban
    :param ban_option: ban or unban
    :return:
    """
    list_of_ip = None
    if ip_addresses.name.endswith('.txt'):  # some very heavy development :)
        for chunk in ip_addresses.chunks():
            list_of_ip = chunk.split('\n')
            list_of_ip[:] = [item for item in list_of_ip if item != '']
    if ip_addresses.name.endswith('.csv'):  # some very heavy development :)
        for chunk in ip_addresses.chunks():
            list_of_ip = chunk.split('\n')
            list_of_ip[:] = [item for item in list_of_ip if item != '']
    masterList = []
    if list_of_ip:
        for ip in list_of_ip:
            masterList.append(ip)
        for ip in masterList:
            time = datetime.utcnow().replace(tzinfo=pytz.utc)
            ban_offender(str(ip), user, reason, time, ban_option, banDuration=-1, forceBan=True)


def generate_blacklist(outputFormat=None):
    """
    generates flacklist
    :param outputFormat: format for firewall(plain html)
    :return: blacklist
    """
    offenders = Offenders.objects.filter(blacklisted=True)
    blacklist = []

    if outputFormat == "firewall":
        blacklist = ""

    for offender in offenders:
        # If I'm just a string output to be firewall consumed
        if isinstance(blacklist, str):
            if not blacklist:
                blacklist = str(offender).strip() + "\n"
            else:
                blacklist = blacklist + str(offender) + "\n"
        # Else just put me in a list
        else:
            blacklist.append(offender.ip)
    return blacklist


def reconcile_bans():
    """
    checks if ip is up for unban
    if so, unbans the ip
    :return:
    """
    time_right_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    offenders = Offenders.objects.filter(Q(blacklisted=True) & ~Q(blacklist_removal_date=None))
    for offender in offenders:
        if offender.blacklist_removal_date <= time_right_now:
            ban_offender(offender.ip, ban_user, unban_reason, time_right_now, ban_option=False)


"""
# RANDOM TESTS


# log_event(
#     create_event(
#         '192.162.1.1',
#         '192.123.2.2',.
#         datetime.utcnow(),
#         'tcp',
#         'ssh',
#         'arista1.aristanetworks.com',
#         'SSH',
#     )
# )
# x = datetime.utcnow().replace(tzinfo=pytz.utc)

# add_offender('142.162.1.1', x, '192.123.2.2')
# print whitelist()
# ban_offender('64568', ban_user, ban_reason, ban_option=False)
# x = datetime.utcnow().replace(tzinfo=pytz.utc)
# create_event('?6789?', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('109.106.61.130', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('157.65.138.144', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('25.91.205.37', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('74.61.0.45', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('136.182.7.36', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('165.136.63.108', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# create_event('170.208.149.48', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
# ban_offender('?6789?', ban_user, ban_reason, x, False)
# ban_offenders('ip.csv', ban_user, ban_reason, False)
# generate_blacklist()
# reconcile_bans()
# get_whitelist_subnets()
# ip_in_range("11.2.4.9", "10.0.0.0/8")

"""
# x = datetime.utcnow()
# create_event('170.208.149.48', '192.123.2.2', x, 'ptc', 'arista p', 'hostN', 'userN')
