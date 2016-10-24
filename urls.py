from django.conf.urls import url

import views

urlpatterns = [
    url(r'^blacklist/', views.blacklist, name="blacklist"),
    url(r'^$', views.blacklist, name="blacklist"),
    url(r'^events/', views.events, name="events"),
    url(r'^banevents/', views.ban_events, name="ban_events"),
    url(r'^offenders/', views.offenders, name="offenders"),
    url(r'^home/', views.responsive, name="home"),
    url(r'^ban/', views.ban, name="home"),
]
