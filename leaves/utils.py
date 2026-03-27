"""Utility functions for leave management system."""
from random import random
import logging
import datetime
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from leavesystem import settings
from django.core.mail import EmailMultiAlternatives
from django.core.cache import cache
import secrets

logger = logging.getLogger(__name__)


def calculate_working_days(start_date, end_date):
    """Calculate the number of working days between two dates."""
    working_days = 0

    if start_date > end_date:
        raise ValueError("Start date cannot be after end date.")
        return 0

    current_date = start_date
    while current_date <= end_date:
        if current_date.weekday() < 5:
            working_days += 1
        current_date += datetime.timedelta(days=1)
    return working_days

def generate_password_set_link(employee):
    """Generate a password set link for the given user."""
    token = default_token_generator.make_token(employee)
    uid = urlsafe_base64_encode(force_bytes(employee.pk))
    frontend_url = settings.FRONTEND_URL
    reset_link = f"{frontend_url}/set-password/{uid}/{token}/"
    return reset_link

def send_email(employee, subject, html_body) -> bool:
    """Send an email to an employee."""
    try:
        msg = EmailMultiAlternatives(
            subject = subject,
            body = "This is a fallback text version",
            from_email = settings.DEFAULT_FROM_EMAIL,
            to = [employee.email]
        )
        msg.attach_alternative(html_body, "text/html")
        msg.send()
        logger.info(f"Email sent successfully to {employee.email}.")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {employee.email}: {str(e)}")
        return False


def send_welcome_email(employee) -> bool:
    """Send the welcome email with the password setup link."""
    set_link = generate_password_set_link(employee)
    html_body = f"""
        <p>Hi {employee.first_name},</p>
        <p>Welcome to the Leave Management System.</p>
        <p>Please click the link below to set your password:</p>
        <p><a href=\"{set_link}\">Set your password</a></p>
        <p>If you did not request this, please contact your administrator.</p>
        <p>Best regards,<br>Team Impact University</p>
    """
    return send_email(employee, "Welcome to the Leave Management System", html_body)

def send_otp_email(employee) -> bool:
    """Send an OTP email to the employee for password reset."""
    otp = generate_otp(employee)
    html_body = f"""
        <p>Hi {employee.first_name},</p>
        <p>Your OTP for password reset is: <strong>{otp}</strong></p>
        <p>This OTP will expire in 10 minutes. If you did not request a password reset, please ignore this email.</p>
        <p>Best regards,<br>Team Impact University</p>
    """
    return send_email(employee, "Password Reset OTP", html_body)


def generate_otp(employee):
    """Generate and cache an OTP for the given employee."""
    otp = secrets.randbelow(900000) + 100000
    cache_key = f"otp_{employee.pk}"
    cache.set(cache_key, otp, timeout=600)  # Cache OTP for 10 minutes
    return otp

def verify_otp(employee, otp):
    """Verify the provided OTP against the cached value."""
    cache_key = f"otp_{employee.pk}"
    cached_otp = cache.get(cache_key)
    if cached_otp and str(cached_otp) == str(otp):
        cache.delete(cache_key)  # Invalidate OTP after successful verification
        return True
    return False


def send_login_otp_email(employee) -> bool:
    """Send an OTP email to the employee for login verification."""
    otp = random.randint(100000, 999999)
    html_body = f"""
        <p>Hi {employee.first_name},</p>
        <p>Your OTP for login verification is: <strong>{otp}</strong></p>
        <p>This OTP will expire in 10 minutes. If you did not attempt to log in, please secure your account immediately.</p>
        <p>Best regards,<br>Team Impact University</p>
    """
    return send_email(employee, "Login Verification OTP", html_body)

def send_password_reset_email(employee, reset_link):
    """Send a password reset email to the employee."""
    subject = "Password Reset Request - Leave Management System"
    message = f"""\
        Hi {employee.first_name},
        
        \n\nYou have requested a password reset for your Leave Management System account.
        
        Please click the following link to reset your password:
        \n\n{reset_link}\n\n

        The link will expire in 24 hours. If you did not request this password reset, 
        please ignore this email and contact your administrator if you have any concerns.

        
        Best regards,
        \n Team Impact University.

        """
    send_email(employee, subject, message)