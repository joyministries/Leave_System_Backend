from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from datetime import date
from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from uuid import uuid4


class Institution(models.Model):
    """Represents an institution (e.g. a university campus or company branch)."""

    name = models.CharField(max_length=255, unique=True)
    allowed_leave_types = models.ManyToManyField(
        "LeaveType",
        blank=True,
        related_name="allowed_institutions",
        help_text="Leave types allowed/enabled for this institution branch.",
    )

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


class Permission(models.Model):
    """
    A single grantable action. The *set* of codes is fixed by the codebase (views check
    for specific codes) — what's dynamic is which roles include which codes.
    Seeded once via the seed_rbac management command (Section 5); not user-creatable.
    """
    code = models.CharField(max_length=100, unique=True, help_text="e.g. 'leave.approve'")
    label = models.CharField(max_length=255)
    category = models.CharField(max_length=50, blank=True, help_text="e.g. 'Leave', 'Employee'")

    class Meta:
        ordering = ["category", "code"]

    def __str__(self):
        return self.code


class Role(models.Model):
    """
    A named bundle of permissions. institution=None is a system template role,
    shared as a starting point across every institution. institution=<X> is a role
    that only exists for, and can only be assigned within, institution X.
    """

    class DataScope(models.TextChoices):
        OWN = "OWN", "Own records only"
        INSTITUTION = "INSTITUTION", "Everything in their own institution"
        GLOBAL = "GLOBAL", "Everything, across all institutions"

    name = models.CharField(max_length=100)
    institution = models.ForeignKey(
        Institution,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="roles",
        help_text="Null = system-wide template. Set = custom role scoped to one institution.",
    )
    data_scope = models.CharField(
        max_length=20, choices=DataScope.choices, default=DataScope.OWN
    )
    permissions = models.ManyToManyField(Permission, related_name="roles", blank=True)
    is_system = models.BooleanField(
        default=False,
        help_text="Seeded default role (STAFF/MANAGER/HR/DIRECTOR/ADMIN). Cannot be deleted.",
    )
    grants_django_admin = models.BooleanField(
        default=False,
        help_text="Mirrors the old is_staff logic — controls Django admin login access.",
    )

    class Meta:
        unique_together = ("name", "institution")
        ordering = ["institution__name", "name"]

    def __str__(self):
        scope = self.institution.name if self.institution else "System"
        return f"{self.name} [{scope}]"

    def has_permission(self, code: str) -> bool:
        return self.permissions.filter(code=code).exists()

    def clean(self):
        if self.is_system and self.institution_id:
            raise ValidationError("System roles cannot be scoped to a single institution.")


class InstitutionSettings(models.Model):
    """
    Institution-level toggles that used to be hardcoded in views/serializers.
    One row per institution; created on demand via get_or_create.
    """

    institution = models.OneToOneField(
        Institution, on_delete=models.CASCADE, related_name="settings"
    )
    default_role = models.ForeignKey(
        Role,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        help_text="Role auto-assigned to employees created without an explicit role.",
    )
    allow_self_cancel = models.BooleanField(
        default=True, help_text="Whether STAFF-scope employees may cancel their own pending leave."
    )
    require_second_approval_over_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="If set, requests longer than this many days need a second approver "
        "(enforced in update_status once a two-step workflow exists — see brainstorm doc).",
    )
    max_consecutive_leave_days = models.PositiveIntegerField(null=True, blank=True)

    def __str__(self):
        return f"Settings for {self.institution.name}"


class Employee(AbstractUser):
    """
    Custom user model — uses email as the login field.

    Roles control dashboard routing and data visibility.
    """

    username = None

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True)
    role = models.ForeignKey(
        "Role",
        on_delete=models.PROTECT,
        related_name="employees",
        null=True,
        blank=True,
        help_text="Determines what this employee can do. See Role.permissions.",
    )
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

    def has_permission(self, code: str) -> bool:
        """Central check used by every permission class below."""
        return bool(self.role and self.role.has_permission(code))

    @property
    def role_name(self):
        return self.role.name if self.role else None

    def save(self, *args, **kwargs):
        self.is_staff = bool(self.role and self.role.grants_django_admin)
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["last_name", "first_name", "email"]


class LeaveType(models.Model):
    """
    Configurable leave types (Annual, Sick, Study, etc.).
    max_days is the *paid* entitlement. Any days beyond this are unpaid.
    institution=None represents a system-wide default template.
    institution=<X> represents a custom leave type available only to that branch.
    """

    name = models.CharField(
        max_length=100,
        help_text="e.g. Annual Leave, Sick Leave, Family Responsibility Leave, Study Leave",
    )
    institution = models.ForeignKey(
        Institution,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="leave_types",
        help_text="Null = system-wide template. Set = custom leave type scoped to one institution.",
    )
    max_days = models.PositiveIntegerField(
        help_text="Maximum number of *paid* days allowed per leave application"
    )

    allowed_months = models.JSONField(
        blank=True,
        null=True,
        default=None,
        help_text=(
            "List of months (1–12) when this leave may be taken. "
            "e.g. [1, 6, 12] means January, June, and December. "
            "Leave null/empty for year-round availability."
        ),
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this leave type is available for new applications",
    )

    class Meta:
        unique_together = ("name", "institution")
        ordering = ["institution__name", "name"]
        verbose_name = "Leave Type"
        verbose_name_plural = "Leave Types"

    def __str__(self):
        scope = self.institution.name if self.institution else "System"
        return f"{self.name} [{scope}] — {self.max_days} paid days"


class Leave(models.Model):
    """
    A single leave application.

    Key design decisions:
    - extra_unpaid_days is calculated automatically in perform_create, never
      expected from the frontend.
    - CANCELLED is a terminal status — cannot be undone.
    - supporting_document is required for Sick Leave and Study Leave.
    - Employees may upload/replace supporting_document on PENDING or APPROVED
      sick/study leaves via the upload_document endpoint.
    """

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"
        CANCELLED = "CANCELLED", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    employee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="leaves",
    )
    institution = models.ForeignKey(
        Institution,
        on_delete=models.CASCADE,
        related_name="leaves",
        null=True,
        blank=True,
        editable=False,
        help_text="Denormalized from employee.institution at creation time.",
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

    def save(self, *args, **kwargs):
        if self.employee_id and not self.institution_id:
            self.institution = self.employee.institution
        super().save(*args, **kwargs)

    def clean(self):
        if self.start_date and self.end_date:
            if self.end_date < self.start_date:
                raise ValidationError("End date cannot be before start date.")
            if self.duration <= 0:
                raise ValidationError("Leave duration must be at least one day.")

            if self.leave_type_id and self.leave_type.allowed_months:
                allowed = self.leave_type.allowed_months
                if (
                    self.start_date.month not in allowed
                    or self.end_date.month not in allowed
                ):
                    month_names = ", ".join(
                        date(2000, m, 1).strftime("%B") for m in sorted(allowed)
                    )
                    raise ValidationError(
                        f"This {self.leave_type.name} can only be taken in: {month_names}."
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


class Notification(models.Model):
    class NotificationType(models.TextChoices):
        LEAVE_SUBMITTED = "LEAVE_SUBMITTED", "Leave Submitted"
        LEAVE_APPROVED = "LEAVE_APPROVED", "Leave Approved"
        LEAVE_REJECTED = "LEAVE_REJECTED", "Leave Rejected"
        LEAVE_CANCELLED = "LEAVE_CANCELLED", "Leave Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    notification_type = models.CharField(
        max_length=30, choices=NotificationType.choices
    )
    leave = models.ForeignKey(
        Leave,
        on_delete=models.CASCADE,
        related_name="notifications",
        null=True,
        blank=True,
    )
    message = models.CharField(max_length=255)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["recipient", "is_read"])]

    def __str__(self):
        return f"Notification for {self.recipient.email}: {self.notification_type}"

