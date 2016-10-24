from django.contrib import admin
from models import Event, Offenders, Whitelist, Ban_Events


# Register your models here.
class OffendersAdmin(admin.ModelAdmin):
    list_display = [
        # 'id',
        'ip',
        'strikes',
        'total_strikes',
        'blacklisted',
    ]


class EventAdmin(admin.ModelAdmin):
    pass


class WhitelistAdmin(admin.ModelAdmin):
    pass


class Ban_EventsAdmin(admin.ModelAdmin):
    pass


admin.site.register(Offenders, OffendersAdmin)
admin.site.register(Event, EventAdmin)
admin.site.register(Whitelist, WhitelistAdmin)
admin.site.register(Ban_Events, Ban_EventsAdmin)
