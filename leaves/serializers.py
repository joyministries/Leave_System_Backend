import logging
from .models import Leave, Employee, LeaveType, Institution, LeaveBalance
from .utils import calculate_working_days
from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from datetime import date
from django.core.files.storage import default_storage

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Institution
# ---------------------------------------------------------------------------


class InstitutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Institution
        fields = ["id", "name"]


# ---------------------------------------------------------------------------
# Employee
# ---------------------------------------------------------------------------


class EmployeeSerializer(serializers.ModelSerializer):
    leave_count = serializers.SerializerMethodField()
    institution_name = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "department",
            "position",
            "role",
            "institution",
            "institution_name",
            "leave_count",
            "must_reset_password",
            "is_active",
        ]

    def get_institution_name(self, obj):
        return obj.institution.name if obj.institution else None

    def get_leave_count(self, obj):
        # Uses the pre-fetched count from annotate() when available
        return getattr(obj, "leave_count_annotation", None) or obj.leaves.count()

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class EmployeeCreateSerializer(serializers.ModelSerializer):
    """
    Used by admins to onboard a new employee.

    Flow:
      1. Admin submits this form.
      2. Employee is created with a *unusable* password (account locked).
      3. An invitation email is sent with a secure uid/token link.
      4. Employee clicks the link → SetPassword view → account activated.
    """

    class Meta:
        model = Employee
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "department",
            "position",
            "role",
            "institution",
            "phone_number",
        ]

    def validate_email(self, value):
        if Employee.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "An employee with this email already exists."
            )
        return value

    def create(self, validated_data):
        """
        Create a locked account and flag it for password reset via email link.
        The account is inactive until the employee sets their own password.
        """
        employee = Employee(**validated_data)
        # set_unusable_password() makes authentication impossible until
        # the employee sets their own password via the invite link.
        employee.set_unusable_password()
        employee.is_active = False
        employee.must_reset_password = True
        employee.save()
        return employee


class EmployeeUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = [
            "email",
            "first_name",
            "last_name",
            "department",
            "position",
            "role",
            "institution",
            "phone_number",
            "must_reset_password",
            "is_active",
        ]


# ---------------------------------------------------------------------------
# Password / Auth
# ---------------------------------------------------------------------------


class SetPasswordSerializer(serializers.Serializer):
    """
    Validates a uid/token pair from an invitation or password-reset email
    and sets a new password.
    """

    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )

        try:
            uid = force_str(urlsafe_base64_decode(data["uid"]))
            employee = Employee.objects.get(pk=uid)
        except (Employee.DoesNotExist, ValueError, TypeError):
            raise serializers.ValidationError({"uid": "Invalid or expired link."})

        if not default_token_generator.check_token(employee, data["token"]):
            raise serializers.ValidationError(
                {"token": "This link is invalid or has already been used."}
            )

        data["employee"] = employee
        return data

    def save(self):
        employee = self.validated_data["employee"]
        employee.set_password(self.validated_data["new_password"])
        employee.is_active = True
        employee.must_reset_password = False
        employee.save(update_fields=["password", "is_active", "must_reset_password"])
        return employee


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class PostLoginPasswordSerializer(serializers.Serializer):
    """Used when a user who is already authenticated must change their password."""

    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )
        return data

    def save(self, employee):
        employee.set_password(self.validated_data["new_password"])
        employee.must_reset_password = False
        employee.save(update_fields=["password", "must_reset_password"])
        return employee


# ---------------------------------------------------------------------------
# Leave Type
# ---------------------------------------------------------------------------


class LeaveTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveType
        fields = ["id", "name", "max_days", "allowed_month", "is_active"]


# ---------------------------------------------------------------------------
# Leave Balance
# ---------------------------------------------------------------------------


class LeaveBalanceSerializer(serializers.ModelSerializer):
    """
    Serializes a single leave balance row enriched with type metadata
    and the computed days_remaining value.
    """

    leave_type_name = serializers.ReadOnlyField(source="leave_type.name")
    max_days = serializers.ReadOnlyField(source="leave_type.max_days")
    allowed_month = serializers.ReadOnlyField(source="leave_type.allowed_month")
    days_remaining = serializers.SerializerMethodField()

    class Meta:
        model = LeaveBalance
        fields = [
            "id",
            "leave_type",
            "leave_type_name",
            "max_days",
            "days_used",
            "days_remaining",
            "year",
        ]

    def get_days_remaining(self, obj):
        return obj.days_remaining


# ---------------------------------------------------------------------------
# Leave
# ---------------------------------------------------------------------------


class LeaveSerializer(serializers.ModelSerializer):
    employee = serializers.PrimaryKeyRelatedField(read_only=True)
    employee_name = serializers.SerializerMethodField()
    leave_type_name = serializers.ReadOnlyField(source="leave_type.name")
    institution_name = serializers.SerializerMethodField()
    leave_duration = serializers.SerializerMethodField()
    paid_days = serializers.SerializerMethodField()
    supporting_document_url = serializers.SerializerMethodField()

    # extra_unpaid_days is calculated server-side; never writable from the client
    extra_unpaid_days = serializers.IntegerField(read_only=True)

    class Meta:
        model = Leave
        fields = [
            "id",
            "employee",
            "employee_name",
            "leave_type",
            "leave_type_name",
            "institution_name",
            "start_date",
            "end_date",
            "reason",
            "status",
            "admin_remarks",
            "supporting_document",
            "supporting_document_url",
            "leave_duration",
            "paid_days",
            "extra_unpaid_days",
        ]
        read_only_fields = ["status", "admin_remarks", "extra_unpaid_days"]

    def get_leave_duration(self, obj):
        return calculate_working_days(obj.start_date, obj.end_date)

    def get_paid_days(self, obj):
        return obj.paid_days

    def get_employee_name(self, obj):
        if obj.employee:
            full_name = f"{obj.employee.first_name or ''} {obj.employee.last_name or ''}".strip()
            return full_name or obj.employee.email
        return None

    def get_institution_name(self, obj):
        if obj.employee and obj.employee.institution:
            return obj.employee.institution.name
        return None

    def get_supporting_document_url(self, obj):
        """
        Generate a signed URL for the supporting document.
        This allows authenticated users to access the document via S3.
        Returns None if no document is attached.
        """
        if not obj.supporting_document:
            return None

        try:
            # Generate a signed URL that expires in 24 hours
            # This ensures the document can be accessed securely
            url = default_storage.url(obj.supporting_document.name)
            return url
        except Exception as e:
            logger.error(f"Error generating signed URL for document {obj.id}: {e}")
            return None

    def validate(self, data):
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        leave_type = data.get("leave_type")
        supporting_document = data.get("supporting_document")

        if start_date and end_date and end_date < start_date:
            raise serializers.ValidationError(
                {"end_date": "end_date cannot be before start_date."}
            )

        if leave_type and not leave_type.is_active:
            raise serializers.ValidationError(
                {"leave_type": f"'{leave_type.name}' is currently inactive."}
            )

        if leave_type and leave_type.allowed_month and start_date and end_date:
            if (
                start_date.month != leave_type.allowed_month
                or end_date.month != leave_type.allowed_month
            ):
                month_name = date(2000, leave_type.allowed_month, 1).strftime("%B")
                raise serializers.ValidationError(
                    {
                        "start_date": f"This leave type can only be taken in {month_name}."
                    }
                )

        if (
            not supporting_document
            and leave_type
            and leave_type.name.lower() in ["sick leave", "study leave"]
        ):
            raise serializers.ValidationError(
                {
                    "supporting_document": "A supporting document is required for this leave type."
                }
            )

        return data


class LeaveStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Leave
        fields = ["status", "admin_remarks"]

    def validate_status(self, value):
        if value not in Leave.Status.values:
            raise serializers.ValidationError("Invalid status value.")
        # Prevent setting back to PENDING via this endpoint
        if value == Leave.Status.PENDING:
            raise serializers.ValidationError(
                "Cannot revert a leave request to Pending."
            )
        return value


# ---------------------------------------------------------------------------
# Leave Summary (for the leave balance table on Dashboard / Admin)
# ---------------------------------------------------------------------------


class LeaveSummarySerializer(serializers.Serializer):
    """
    Aggregated row for the Leave Summary Table shown on Dashboard and Admin pages.

    Each row represents one leave type for one employee and carries:
      - How many leaves of this type they have taken (any status)
      - The most recent leave's dates
      - The allocated (max) paid days
      - The balance remaining for the current year
    """

    leave_type_id = serializers.IntegerField()
    leave_type_name = serializers.CharField()
    max_days = serializers.IntegerField()
    allowed_month = serializers.IntegerField(allow_null=True)
    days_used = serializers.DecimalField(max_digits=5, decimal_places=1)
    days_remaining = serializers.DecimalField(max_digits=5, decimal_places=1)
    last_start_date = serializers.DateField(allow_null=True)
    last_end_date = serializers.DateField(allow_null=True)
    last_duration = serializers.IntegerField(allow_null=True)
    total_applications = serializers.IntegerField()
    is_active = serializers.BooleanField()
    status = serializers.CharField(allow_null=True)
