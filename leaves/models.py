from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from datetime import date
from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from uuid import uuid4

class Institution(models.Model):
    """Model representing an institution in the leave management system.
    Each institution has a unique name and can have multiple employees associated with it.
    """
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Institution"
        verbose_name_plural = "Institutions"
        ordering = ["name"]


class EmailUserManager(BaseUserManager):
    """Custom user manager to handle user creation with email as the unique identifier."""

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user with the given email and password."""
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class Employee(AbstractUser):
    """Model representing an employee in the leave management system.
    Each employee is associated with a Django User for authentication and has additional fields for department, position, email, and phone number.

    Fields:
        employee_department: CharField to store the department of the employee.
        employee_position: CharField to store the position of the employee.
        phone_number: CharField to store the phone number of the employee.
    """

    class Role(models.TextChoices):
        STAFF = "STAFF", "Staff"
        MANAGER = "MANAGER", "Manager"
        HR = "HR", "HR"
        ADMIN = "ADMIN", "Admin"

    username = None

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.STAFF)
    institution = models.ForeignKey(
        Institution,
        on_delete=models.CASCADE,
        related_name="employees",
        default=None,
        blank=True,
        null=True,
    )
    must_reset_password = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    objects = EmailUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
        "department",
        "position",
        "institution",
        "role",
    ]

    def __str__(self):
        return (
            f"{self.first_name} {self.last_name} ({self.department} - {self.position})"
        )

    def save(self, *args, **kwargs):
        """
        Automatically set is_staff based on role.
        Only HR and above get Django admin access.
        """
        if self.role in [self.Role.HR]:
            self.is_staff = True
        else:
            self.is_staff = False

        super().save(*args, **kwargs)


class LeaveType(models.Model):
    """Model representing a leave type in the leave management system.
    Each leave type has a unique ID, name, type, start and end dates, reason for the leave, and an optional supporting document.
    """
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="e.g Annual Leave, Sick Leave, Family Responsibility Leave, Study Leave",
    )
    max_days = models.PositiveIntegerField(
        help_text="Maximum number of days allowed for this leave type"
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Leave Type"
        verbose_name_plural = "Leave Types"

    def __str__(self):
        return f"{self.name} - {self.max_days} days"


class Leave(models.Model):
    """Model representing a leave request in the leave management system.
    Each leave request has a unique ID, name, type, start and end dates, reason for the leave, and an optional supporting document.
    """

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    employee = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="leaves"
    )
    leave_type = models.ForeignKey(
        LeaveType, on_delete=models.PROTECT, related_name="leaves"
    )
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()
    supporting_document = models.FileField(
        upload_to="leave_documents/", blank=True, null=True
    )
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    admin_remarks = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ["-id"]

    def clean(self):
        """Custom validation to ensure that the end date is not before the start date and that the start date is not in the past."""
        if self.start_date and self.end_date:
            length_of_leave = (self.end_date - self.start_date).days + 1

            if self.end_date < self.start_date:
                raise ValidationError("End date cannot be before start date.")
            if self.start_date < date.today():
                raise ValidationError("Start date cannot be in the past.")
            if length_of_leave <= 0:
                raise ValidationError("Leave duration must be at least one day.")

    @property
    def duration(self):
        """Calculate the duration of the leave in days."""
        return (self.end_date - self.start_date).days + 1

    def __str__(self):
        # Use the employee's full name (or email) plus leave type and dates
        employee_display = (
            getattr(self.employee, "get_full_name", lambda: "")() or self.employee.email
        )
        return f"{employee_display} - {self.leave_type} from {self.start_date} to {self.end_date}"
