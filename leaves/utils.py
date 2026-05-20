"""Utility functions for leave management system."""
import logging
import datetime
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from leavesystem import settings
from django.core.mail import EmailMultiAlternatives
from django.http import JsonResponse
from django.template.loader import render_to_string
from .models import Employee

logger = logging.getLogger(__name__)

def calculate_working_days(start_date, end_date):
    """Calculate the number of leave days between two dates (inclusive of weekends)."""
    if start_date > end_date:
        raise ValueError("Start date cannot be after end date.")

    return (end_date - start_date).days + 1


def calculate_end_date_from_days(start_date, num_days):
    """
    Calculate the exact end date by adding a specific number of calendar days
    (including weekends) to a start date.
    """
    if num_days <= 0:
        # If they have 0 balance, the paid portion technically ended yesterday.
        return start_date - datetime.timedelta(days=1)

    # num_days is inclusive of start_date, so we advance by (num_days - 1)
    return start_date + datetime.timedelta(days=num_days - 1)

def link_generator(user):
    """Generate a unique link for password reset or account activation."""
    token = default_token_generator.make_token(user)
    uuid = urlsafe_base64_encode(force_bytes(user.pk))
    link = f"{settings.FRONTEND_URL}/set-password/{uuid}/{token}/"
    return link

def send_account_creation_email(employee):
    """ Send an email to the employee when the account is created"""
    full_name = f"{employee.first_name} {employee.last_name}".strip()
    link = link_generator(employee)
    
    html_content = render_to_string(
        'emails/email.html', {
            'user_name': full_name if full_name else employee.email,
            'email': employee.email,
            'link': link,
        })
    
    message = EmailMultiAlternatives(
        subject='Welcome to the Leave Management System',
        body=html_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[employee.email],
    )

    message.content_subtype = 'html'
    message.send()

    return JsonResponse({'message': 'Email sent successfully.'})

def send_password_reset_email(employee):
    """Send a password reset email to the employee."""
    reset_link = link_generator(employee)

    full_name = f"{employee.first_name} {employee.last_name}".strip()
    html_content = render_to_string(
        'emails/password_reset_email.html', {
            'user_name': full_name if full_name else employee.email,
            'reset_link': reset_link,
        })

    message = EmailMultiAlternatives(
        subject='Password Reset Request',
        body=html_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[employee.email],
    )

    message.content_subtype = 'html'
    message.send()

    return JsonResponse({'message': 'Password reset email sent successfully.'})

def leave_request_status_email(employee, leave_request, email_type):
    """Send a general email related to leave requests (approval, or rejection)."""
    full_name = f"{employee.first_name} {employee.last_name}".strip()
    
    if email_type == 'approval':
        subject = 'Your Leave Request Has Been Approved'
        template = 'emails/leave_approval_email.html'
    elif email_type == 'rejection':
        subject = 'Your Leave Request Has Been Rejected'
        template = 'emails/leave_rejection_email.html'
    elif email_type == 'cancellation':
        subject = 'You have cancelled your leave request'
        template = 'emails/leave_cancellation_email.html'
    else:
        logger.error(f"Invalid email type: {email_type}")
        return JsonResponse({'error': 'Invalid email type.'}, status=400)

    html_content = render_to_string(template, {
        'user_name': full_name if full_name else employee.email,
        'leave_start_date': leave_request.start_date,
        'leave_end_date': leave_request.end_date,
        'leave_type': leave_request.leave_type.name,
        'leave_reason': leave_request.reason,
        'dashboard_url': f"{settings.FRONTEND_URL}/dashboard/",
    })

    message = EmailMultiAlternatives(
        subject=subject,
        body=html_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[employee.email],
    )

    message.content_subtype = 'html'
    message.send()

    return JsonResponse({'message': f'{email_type.capitalize()} email sent successfully.'})

def leave_request_submitted_email(employee, leave_request):
    """Send an email to the employee when a leave request is submitted."""
    full_name = f"{employee.first_name} {employee.last_name}".strip()
    
    html_content = render_to_string('emails/leave_request_email.html', {
        'user_name': full_name if full_name else employee.email,
        'leave_start_date': leave_request.start_date,
        'leave_end_date': leave_request.end_date,
        'leave_type': leave_request.leave_type.name,
        'leave_reason': leave_request.reason,
        'dashboard_url': f"{settings.FRONTEND_URL}/dashboard/",
    })

    message = EmailMultiAlternatives(
        subject='Your Leave Request Has Been Submitted',
        body=html_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[employee.email],
    )

    message.content_subtype = 'html'
    message.send()

    return JsonResponse({'message': 'Leave request email sent successfully.'})


def leave_request_notification_email(employee, leave_request):
    """Send a notification email to the relevant Managers, HR, and Admins."""

    # Override: Send all notification emails to a specific administrator defined in settings
    recipient_emails = [settings.LEAVE_NOTIFICATION_EMAIL]

    full_name = f"{employee.first_name} {employee.last_name}".strip()
    
    html_content = render_to_string('emails/leave_request_notification_email.html', {
        'user_name': full_name or employee.email,
        'leave_start_date': leave_request.start_date,
        'leave_end_date': leave_request.end_date,
        'leave_type': leave_request.leave_type.name,
        'leave_reason': leave_request.reason,
        'dashboard_url': f"{settings.FRONTEND_URL}/dashboard/",
    })

    message = EmailMultiAlternatives(
        subject=f'New Leave Request Submitted by {full_name or employee.email}',
        body=html_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=recipient_emails,
        reply_to=[employee.email],
    )

    message.content_subtype = 'html'
    
    message.send(fail_silently=False)

    return JsonResponse({'message': 'Leave request notification email sent successfully.'})