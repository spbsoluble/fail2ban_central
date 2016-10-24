from datetime import datetime

import pytz
from django.http import HttpResponseRedirect
from django.shortcuts import render, render_to_response
from django.views.decorators.csrf import csrf_exempt

from Fail2BanDB import ban_offender, ban_offenders, create_event, reconcile_bans
from Fail2BanDB import generate_blacklist
from forms import PostForm, UploadFileForm
from models import Event, Ban_Events, Offenders, IP_Upload_List

"""
uncomment or comment to toggle async file upload
celery -A tasks worker --loglevel=info
run in f2BAN/fail2ban
"""


def responsive(request):
    return render(request, 'responsive.html', {})


def ban(request):
    messages = {
        'successes': [],
        'warnings': [],
        'errors': [],
        'debug': [],
    }
    form = {}
    if request.GET:
        if request.GET.get("reconsile"):
            reconcile_bans()
            return render(request, 'offenders.html')
        else:
            print "I'm trying to ban stuff"
            offenderIP = request.GET.get("offender_ip")
            targetHostname = request.GET.get("target_hostname")
            targetIP = request.GET.get("target_ip")
            port = request.GET.get("port")
            protocol = request.GET.get("protocol")
            name = request.GET.get("name")
            output = create_event(ip=offenderIP, target_ip=targetIP, time=None, protocol=protocol, port=port,
                                  hostname=targetHostname, name=name)
            return render(request, 'offenders.html', {'message': output})

    elif request.POST:
        messages['debug'].append("POST data: %s" % request.POST)
        messages['debug'].append("FILE data: %s" % request.FILES)
        form['bulk'] = request.POST.get('bulk')

        if form['bulk']:
            # Logic for the bulk ban form
            if request.FILES:
                # Handle uploaded files
                print "Passing user %s" % request.user
                output = _handle_file_upload(request.FILES, str(request.user))
                messages['errors'] += output['errors']
                messages['successes'] += output['successes']
            else:
                form['subnet'] = request.POST.get('subnet_bulk')
                form['offender_ip'] = request.POST.get('offender_ip_bulk')
                form['duration'] = request.POST.get('ban_duration_bulk')
                form['reason'] = request.POST.get('reason_bulk')
                form['file'] = request.FILES.get('bulk_file')
                form['tags'] = request.POST.get('tags_bulk')
                form['user'] = request.user
                form['subnet'] = request.POST.get('subnet_bulk')
                try:
                    output = ban_offender(
                        form['offender_ip'], request.user, form['reason'], datetime.utcnow(), 1, form['duration'], True,
                        form['subnet']
                    )
                    if output and 'failure' in output.lower():
                        messages['errors'].append(output)
                    else:
                        success_message = "%s%s has been added to the <a href='/fail2ban/blacklist'>blacklist</a>" % (
                            form['offender_ip'], form['subnet'])
                        messages['successes'].append(success_message)

                except:
                    messages['errors'].append(
                        "Unable to ban %s%s. Please try again." % (form['offender_ip'], form['subnet']))
                messages['debug'].append(output)

        else:
            # Else I must be trying a single ban
            form['user'] = request.user
            form['offender_ip'] = request.POST.get('offender_ip')
            form['duration'] = request.POST.get('ban_duration')
            form['reason'] = request.POST.get('reason')
            form['tags'] = request.POST.get('tags')
            output = ban_offender(form['offender_ip'], request.user, form['reason'], datetime.utcnow(), 1,
                                  form['duration'], True)
            if output and 'failure' in output.lower():
                messages['errors'].append(output)
            else:
                success_message = "%s%s has been added to the <a href='/fail2ban/blacklist'>blacklist</a>" % (
                    form['offender_ip'], '/32')
                messages['successes'].append(success_message)

            messages['debug'].append(output)
    else:
        form = True
    # form = PostForm(request.POST)
    form1 = UploadFileForm(request.POST, request.FILES)
    return render(request, 'responsive.html', {
        'form1': form1, 'form': form, 'errors': messages['errors'], 'debug': messages['debug'],
        'successes': messages['successes']
    })


def _handle_file_upload(file, user):
    print "I got %s as a user" % user
    if isinstance(file, list):
        for file_object in file:
            return _handle_file_upload(file_object, user)
    elif isinstance(file, dict):
        return _handle_file_upload(file['bulk_file'], user)
    else:
        try:
            uploadList = IP_Upload_List(
                name=file.name,
                uploadedBy=user,
                content=file,
                uploadDate=datetime.utcnow()
            )
            uploadList.save()
        except:
            message = "Failed to save file"

        import csv, codecs
        file.open()
        reader = csv.reader(codecs.EncodedFile(file, "utf-8"), delimiter=',', quotechar='"')
        messages = {
            'successes': [],
            'warnings': [],
            'errors': [],
            'debug': [],
        }
        for line in list(reader):
            print line
            ipAddress = line[0]
            subnet = line[1]
            tags = None
            try:
                tags = line[4]
            except IndexError:
                print "No tags found"

            reason = "Manual Ban"
            try:
                reason = line[3]
            except IndexError:
                print "No reason found; using default"

            duration = -1
            try:
                duration = line[2]
            except IndexError:
                print "No duration found using default -1"

            print "My user is %s" % user
            if not user:
                user = 'Fail2BanDB'
            banStatus = ban_offender(
                line[0], user, reason, datetime.utcnow(), 1, duration, True, subnet, tags)

            if banStatus:
                messages['errors'].append(banStatus)
            else:
                messages['successes'].append(
                    "%s%s has been added to the <a href='/fail2ban/blacklist'>blacklist</a>" % (ipAddress, subnet))

        if len(messages['errors']) > 0:
            messages['errors'] = messages['errors'][1:]
        print "Returning: %s" % messages
        return messages


def manualBan(request):
    form = PostForm(request.POST)
    form1 = UploadFileForm(request.POST, request.FILES)
    return render(request, 'responsive.html', {'form1': form1})


@csrf_exempt
def blacklist(request, messages=None):
    """
    generates the blacklist: either in plain html or in website
    :param request: request
    :return:
    """
    content = None

    if not messages:
        messages = {
            'errors': [],
            'successes': [],
            'warnings': [],
        }
    valid_formats = ['f2b', 'firewall', 'pan']
    if request.GET:
        outputFormat = request.GET.get('format')
        if outputFormat:
            if outputFormat == 'firewall' or outputFormat == 'pan':
                blacklist = generate_blacklist('firewall')
                return render(request, 'blacklist_firewall.html', {'format': outputFormat, 'blacklist': blacklist})
            elif outputFormat == 'f2b':
                blacklist = generate_blacklist('firewall')
                return render(request, 'blacklist_firewall.html', {'format': outputFormat, 'blacklist': blacklist})
            else:
                blacklist = "Invalid format parameter format=%s. Please use the following %s" % (
                    outputFormat, valid_formats)
                messages['errors'].append(blacklist)

    if request.method == 'POST':
        try:
            form = PostForm(request.POST)
            form1 = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                ban_option = True
                time = datetime.utcnow().replace(tzinfo=pytz.utc)
                ip = request.POST.get('ip')
                ban_duration = request.POST.get('blacklist_duration')
                reason = request.POST.get('reason')
                tag = request.POST.get('tag')
                ban_offender(ip, 'ban_User', reason, time, ban_option, ban_duration, forceBan=True)
                print ip
                print ban_duration
                print reason
                print tag
                return HttpResponseRedirect('/blacklist')
            if form1.is_valid() and request.FILES:
                ban_option = True
                user = 'superUser'
                reason = 'superReason'
                uploadFile = request.FILES['file']
                # banOffendersAsync.delay(uploadFile, user, reason, ban_option)
                ban_offenders(uploadFile, user, reason, ban_option)
                return HttpResponseRedirect('/blacklist')
            else:
                return HttpResponseRedirect('/blacklist')
        except OverflowError:
            return HttpResponseRedirect('/blacklist')
    else:
        form = PostForm(request.POST)
        form1 = UploadFileForm(request.POST, request.FILES)
        blacklist = generate_blacklist()
        offenders = list(
            Offenders.objects.filter(blacklisted=True).values(
                'ip', 'strikes', 'total_strikes', 'last_offense_date',
                'last_offense_target', 'blacklisted', 'subnet_mask',
                'last_blacklisted_date', 'last_blacklist_remove_date',
                'blacklist_duration', 'blacklist_removal_date', 'tag'))

        blackListers = Offenders.objects.filter(blacklisted=True)
        entries = []
        for offender in blackListers:
            entry = {
                'min': {
                    'ip': offender.ip,
                    'subnet': offender.subnet_mask,
                    'blacklisted': offender.blacklisted,
                    'strikes': offender.strikes,
                    'total_strikes': offender.total_strikes,
                    'last_offense_date': offender.last_offense_date,

                },
                'verbose': {
                    'last_offense_target': offender.last_offense_target,
                    'last_blacklisted_date': offender.last_blacklisted_date,
                    'last_blacklist_remove_date': offender.last_blacklist_remove_date,
                    'blacklist_removal_date': offender.blacklist_removal_date,
                    'blacklist_duration': offender.blacklist_duration,
                    'tag': offender.tag,
                }
            }
            entries.append(entry)

        if entries and entries[0]:
            header = [
                'IP',
                'Subnet',
                'Blacklisted',
                'Strikes',
                'Total Strikes',
                'Last Offense',
            ]
        else:
            header = None

        return render(request, 'responsive.html',
                      {'blacklistedIP': entries, 'header': header, 'errors': messages['errors']})


def events(request):
    """
    view for events
    :param request:
    :return:
    """
    # content = {'events': Event.objects.all()}
    events = None
    header = [
        'Offender IP',
        'Target Hostname',
        'Target IP',
        # 'Port',
        # 'Name',
        # 'Protocol',
        'Time',
    ]
    messages = {
        'errors': [],
        'successes': [],
        'warnings': [],
    }
    if request.GET:
        if request.GET.get('max_results'):
            limit = request.GET.get('max_results')
            if limit == "all":
                events = Event.objects.all().values(
                    'offender_ip', 'target_ip', 'time', 'hostname').order_by('-time')
            else:
                events = Event.objects.all().values(
                    'offender_ip', 'target_ip', 'time', 'hostname', ).order_by('-time')[:limit]

    else:
        events = Event.objects.all().values(
            'offender_ip', 'target_ip', 'time', 'hostname').order_by('-time')[:1000]
        messages['warnings'].append(
            "Only displaying most recent 1000 events for performance reasons. If you want to see more then you'll have to use django admin")

    return render(request, 'responsive.html',
                  {'events': events, 'header': header, 'errors': messages['errors'], 'warnings': messages['warnings']})


def ban_events(request):
    """
    view for ban events
    :param request:
    :return:
    """
    # content = {'ban_events': Ban_Events.objects.all()}
    content = {'ban_events': Ban_Events.objects.all().values(
        'offender_ip', 'reason', 'user', 'date',
        'action')}

    banEvents = Ban_Events.objects.all()
    entries = []
    for ban in banEvents:
        entry = {
            'min': {
                'ip': ban.offender_ip,
                'reason': ban.reason,
                'user': ban.user,
                'action': ban.action,
                'date': ban.date.strftime("%m-%d-%Y %H:%M:%S %Z"),
            },
        }
        entries.append(entry)

    if entries and entries[0]:
        header = [
            'IP',
            'Reason',
            'User',
            'Action',
            'Date',
        ]
    else:
        header = None

    return render(request, 'responsive.html', {'ban_events': entries, 'header': header})


def offenders(request):
    """
    view for offenders
    :param request:
    :return:
    """
    offenderObjs = Offenders.objects.all().order_by('-last_offense_date')
    entries = []
    for offender in offenderObjs:
        entry = {
            'min': {
                'ip': offender.ip,
                'blacklisted': offender.blacklisted,
                'strikes': offender.strikes,
                'total_strikes': offender.total_strikes,
                'last_offense_date': offender.last_offense_date,

            },
            'verbose': {
                'last_offense_target': offender.last_offense_target,
                'last_blacklisted_date': offender.last_blacklisted_date,
                'last_blacklist_remove_date': offender.last_blacklist_remove_date,
                'blacklist_removal_date': offender.blacklist_removal_date,
                'blacklist_duration': offender.blacklist_duration,
                'tag': offender.tag,
            }
        }
        entries.append(entry)

    if entries and entries[0]:
        header = [
            'IP',
            'Blacklisted',
            'Strikes',
            'Total Strikes',
            'Last Offense',
        ]
    else:
        header = None

    return render(request, 'responsive.html', {'offenders': entries})
