import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Employee
from .utils import send_account_creation_email, leave_request_status_email, leave_request_notification_email, leave_request_submitted_email

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Employee)
def trigger_welcome_email(sender, instance, created, **kwargs):
    """Fallback signal to send a welcome email for users created without a password.

    The main API creation flow always sets a password and explicitly sends the
    welcome email in the view; this signal is only for any other creation paths
    that might create an Employee without a password.
    """
    if created and not instance.password:
        try:
            send_account_creation_email(instance)
            logger.info(
                f"Welcome email sent from post_save signal to {instance.email}."
            )
        except Exception as e:
            # Never let email issues abort the save transaction for this fallback path
            logger.error(
                f"Failed to send welcome email from post_save signal to {instance.email}: {e}"
            )



# Note: Leave-request emails and notifications are handled explicitly in views.py
# (perform_create, update_status, cancel). Signal handlers on Employee cannot
# accurately inspect or process leave operations.