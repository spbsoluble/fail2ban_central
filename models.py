from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Event(models.Model):
    """
    model for an event
    """
    offender_ip = models.CharField(
        max_length=16,
        verbose_name="IP",
    )
    target_ip = models.CharField(
        max_length=15,
        verbose_name="Target IP",
        null=True,
        blank=True,
    )
    time = models.DateTimeField(
        # auto_now_add=True
    )
    protocol = models.CharField(
        max_length=3,
        verbose_name="Protocol",
    )
    port = models.CharField(
        max_length=11,
        verbose_name="Port",
    )
    hostname = models.CharField(
        null=True,
        max_length=50,
        default=None,
        verbose_name="Hostname",
    )
    name = models.CharField(
        null=True,
        max_length=50,
        default=None,
        verbose_name="Name",
    )

    def __str__(self):
        """
        Returns the asset serial Number
        :return: String serial Number
        """
        return str(self.offender_ip)


class Offenders(models.Model):
    """
    model for an offender
    """
    ip = models.CharField(
        primary_key=True,
        max_length=16,
        verbose_name="IP",
    )
    strikes = models.IntegerField(
        default=1,
        verbose_name="Strikes",
    )  # total strikes within ban period
    total_strikes = models.IntegerField(
        default=1,
        verbose_name="Overall Strikes",
    )  # total strikes of an offender
    last_offense_date = models.DateTimeField(
        # auto_now_add=True
        db_index=True,
        verbose_name="Last Offense",
    )
    last_offense_target = models.CharField(
        null=True,
        max_length=15,
        default=None,
        verbose_name="Last Target",
    )
    blacklisted = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name="Blacklisted",
    )
    last_blacklisted_date = models.DateTimeField(
        null=True,
        default=None,
        # auto_now_add=True
        verbose_name="Last Blacklisted",
    )
    last_blacklist_remove_date = models.DateTimeField(
        null=True,
        default=None,
        # auto_now_add=True
        db_index=True,
        verbose_name="Last Removal Date",
    )
    blacklist_duration = models.IntegerField(
        null=True,
        default=None,
        verbose_name="Blacklist Duration",
    )  # how long offender will be on the blacklist
    blacklist_removal_date = models.DateTimeField(
        null=True,
        default=None,
        # auto_now_add=True
        db_index=True,
        verbose_name="Removal Date",
    )  # when offender will be removed

    subnet_mask = models.CharField(
        default="/32",
        db_index=True,
        verbose_name="Subnet",
        max_length=3,
    )

    tag = models.CharField(
        max_length=1024,
        null=True,
        blank=True,
        verbose_name="Tag",
    )

    def __str__(self):
        return self.ip + self.subnet_mask

    def __unicode__(self):
        return self.ip + self.subnet_mask


class Ban_Events(models.Model):
    """
    model for a ban event
    """
    offender_ip = models.CharField(
        max_length=16,
        verbose_name="Attacker IP",
    )
    reason = models.TextField(
        blank=True,
        verbose_name="Reason",
    )
    user = models.CharField(
        max_length=30,
        verbose_name="Reporting User",
    )
    date = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Date",
    )
    action = models.IntegerField(
        verbose_name="Action",
    )


class Whitelist(models.Model):
    """
    model for the whitelist
    """
    ip = models.CharField(
        max_length=255,
        primary_key=True,
        verbose_name="IP",
    )
    date = models.DateTimeField(
        null=True,
        default=None,
        verbose_name="Date",
    )
    user = models.CharField(
        default='f2b admin',
        max_length=255,
        verbose_name="Reporting User",
    )
    reason = models.TextField(
        null=True,
        default=None,
        verbose_name="Reason",
    )


class Blacklist_IP(models.Model):
    """
    Model for the blacklist form on the website. Should not actually have data inside it in the db.
    """
    ip = models.CharField(
        primary_key=True,
        max_length=15,
        verbose_name="IP",
    )
    blacklist_duration = models.IntegerField(
        null=True,
        default=None,
        verbose_name="Blacklist Duration",
    )
    reason = models.TextField(
        null=True,
        default=None,
        verbose_name="Reason",
    )
    tag = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name="Tag",
    )
    file = models.FileField(
        null=True,
        blank=True,
        verbose_name="File",
    )

class IP_Upload_List(models.Model):
    name = models.CharField(
        max_length=255,
        verbose_name="File Name",
    )
    uploadDate = models.DateField(

    )
    content = models.FileField(
        upload_to="/opt/uploads/fail2ban/"
    )
    uploadedBy = models.ForeignKey(User, null=True)