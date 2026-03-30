from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from datetime import date
from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from uuid import uuid4
from django.core.validators import MinValueValidator, MaxValueValidator


class Institution(models.Model):
    """Represents an institution (e.g. a university campus or company branch)."""

    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Institution"
        verbose_name_plural = "Institutions"
        ordering = ["name"]


class EmailUserManager(BaseUserManager):
    """Custom manager — email is the unique identifier, not username."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, password, **extra_fields)


class Employee(AbstractUser):
    """
    Custom user model — uses email as the login field.

    Roles control dashboard routing and data visibility:
      STAFF     → sees only their own records
      MANAGER   → can view and add employees only
      HR        → can view and add employees only (institution-scoped)
      DIRECTOR  → same as Admin (global access)
      ADMIN     → full system access, Django admin
    """

    class Role(models.TextChoices):
        STAFF = "STAFF", "Staff"
        MANAGER = "MANAGER", "Manager"
        HR = "HR", "HR"
        DIRECTOR = "DIRECTOR", "Director"
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
        null=True,
        blank=True,
    )
    # True after admin creates the account — clears after first password set
    must_reset_password = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    # Soft-delete flag — never hard-delete employee records
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
        # Only HR, DIRECTOR, and ADMIN get Django admin access
        self.is_staff = self.role in [self.Role.HR, self.Role.DIRECTOR, self.Role.ADMIN]
        super().save(*args, **kwargs)


class LeaveType(models.Model):
    """
    Configurable leave types (Annual, Sick, Study, etc.).
    max_days is the *paid* entitlement. Any days beyond this are unpaid.
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="e.g. Annual Leave, Sick Leave, Family Responsibility Leave, Study Leave",
    )
    max_days = models.PositiveIntegerField(
        help_text="Maximum number of *paid* days allowed per leave application"
    )

    allowed_month = models.IntegerField(
        blank=True,
        null=True,
        validators=[MinValueValidator(1), MaxValueValidator(12)],
        help_text="Set a specific month (1-12) this leave is restricted to. Leave blank for year round availability.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this leave type is available for new applications",
    )

    class Meta:
        verbose_name = "Leave Type"
        verbose_name_plural = "Leave Types"

    def __str__(self):
        return f"{self.name} — {self.max_days} paid days"


class Leave(models.Model):
    """
    A single leave application.

    Key design decisions:
    - extra_unpaid_days is calculated automatically in perform_create, never
      expected from the frontend.
    - CANCELLED is a terminal status — cannot be undone.
    - supporting_document is required for Sick Leave and Study Leave.
    """

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    employee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="leaves",
    )
    leave_type = models.ForeignKey(
        LeaveType,
        on_delete=models.PROTECT,
        related_name="leaves",
    )
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()
    supporting_document = models.FileField(
        upload_to="leave_documents/",
        blank=True,
        null=True,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    admin_remarks = models.TextField(blank=True, null=True)

    # Calculated on save — days requested beyond the leave type's max_days
    extra_unpaid_days = models.IntegerField(
        default=0,
        help_text="Days beyond the paid entitlement. Displayed to both employee and admin.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            # The three most common query patterns
            models.Index(fields=["employee", "status"]),
            models.Index(fields=["employee", "leave_type"]),
            models.Index(fields=["status"]),
        ]

    def clean(self):
        if self.start_date and self.end_date:
            if self.end_date < self.start_date:
                raise ValidationError("End date cannot be before start date.")
            # Only validate future dates on *new* records
            if not self.pk and self.start_date < date.today():
                raise ValidationError("Start date cannot be in the past.")
            if self.duration <= 0:
                raise ValidationError("Leave duration must be at least one day.")

            if self.leave_type_id and self.leave_type.allowed_month:
                if (
                    self.start_date.month != self.leave_type.allowed_month
                    or self.end_date.month != self.leave_type.allowed_month
                ):
                    raise ValidationError(
                        f"This leave type can only be taken in month {self.leave_type.allowed_month}."
                    )
                month_name = date(2000, self.leave_type.allowed_month, 1).strftime("%B")

                raise ValidationError(
                    f"This {self.leave_type.name} can only be taken in {month_name}."
                )

    @property
    def duration(self):
        """Total calendar days requested (inclusive)."""
        from .utils import calculate_working_days

        if self.start_date and self.end_date:
            return calculate_working_days(self.start_date, self.end_date)
        return 0

    @property
    def paid_days(self):
        """Days covered by the leave type entitlement."""
        return max(0, self.duration - self.extra_unpaid_days)

    def __str__(self):
        name = (
            getattr(self.employee, "get_full_name", lambda: "")() or self.employee.email
        )
        return f"{name} — {self.leave_type} ({self.start_date} → {self.end_date})"


class LeaveBalance(models.Model):
    """
    Tracks how many paid days an employee has *used* per leave type per year.
    One row per employee/leave_type/year combination.

    The balance displayed to the user is:
        remaining = leave_type.max_days - days_used
    """

    employee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="leave_balances",
    )
    leave_type = models.ForeignKey(
        LeaveType,
        on_delete=models.CASCADE,
        related_name="balances",
    )
    year = models.PositiveIntegerField(
        help_text="Calendar year this balance applies to"
    )
    days_used = models.DecimalField(
        max_digits=5,
        decimal_places=1,
        default=0,
        help_text="Paid leave days consumed in this year",
    )

    class Meta:
        unique_together = ("employee", "leave_type", "year")
        indexes = [
            models.Index(fields=["employee", "year"]),
        ]
        verbose_name = "Leave Balance"
        verbose_name_plural = "Leave Balances"

    @property
    def days_remaining(self):
        return max(0, float(self.leave_type.max_days) - float(self.days_used))

    def __str__(self):
        return (
            f"{self.employee} — {self.leave_type.name} "
            f"{self.year}: {self.days_used}/{self.leave_type.max_days} used"
        )
