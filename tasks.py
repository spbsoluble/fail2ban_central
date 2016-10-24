from celery import Celery
import sys

sys.path.append("..")
from Fail2BanDB import ban_offenders

# Configure celery.
celery = Celery('tasks', broker='amqp://guest@localhost//')


@celery.task(name='tasks.banOffendersAsync')  # Decorator which defines the underlying function as a celery task.
def banOffendersAsync(ip_addresses, user, reason, ban_option):
    """
    bans Asynchrounously
    :return:
    """
    ban_offenders(ip_addresses, user, reason, ban_option)
    print 'Banned Everyone'
