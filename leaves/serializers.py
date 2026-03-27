import logging
from datetime import date
from .models import Leave, Employee, LeaveType, Institution
from .utils import calculate_working_days, send_email
from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.utils import timezone
from django.utils.crypto import get_random_string

logger = logging.getLogger(__name__)


# Serializer for Institution model
class InstitutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Institution
        fields = ["id", "name"]


# Serializer for Employee model
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
        return obj.leaves.count()

    def update(self, instance, validated_data):
        """Update employee fields (password is handled via separate SetPassword endpoint)."""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class EmployeeCreateSerializer(serializers.ModelSerializer):
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
        """Create employee with a generated password and set must_reset_password flag."""
        # Generate a random secure password (12 characters)
        password = get_random_string(
            length=12,
            allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()",
        )

        # Create the employee with the generated password
        employee = Employee.objects.create_user(**validated_data, password=password)

        # Set must_reset_password flag after creation
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


class SetPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, data):
        # 1. Check if passwords match
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )

        # 2. Verify User & Token
        try:
            uid = force_str(urlsafe_base64_decode(data["uid"]))
            employee = Employee.objects.get(pk=uid)
        except (Employee.DoesNotExist, ValueError, TypeError):
            raise serializers.ValidationError({"uid": "Invalid or expired link."})

        if not default_token_generator.check_token(employee, data["token"]):
            raise serializers.ValidationError(
                {"token": "Token is invalid or has expired."}
            )

        data["employee"] = employee
        return data

    def save(self):
        employee = self.validated_data["employee"]
        employee.set_password(self.validated_data["new_password"])
        employee.is_active = True  # Activate them now!
        # Clear must_reset_password so subsequent logins behave normally
        employee.must_reset_password = False
        employee.save()
        return employee


# Login Serializer
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class PostLoginPasswordSerializer(serializers.Serializer):
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
        employee.save()
        return employee

class LeaveTypeSerializer(serializers.ModelSerializer):

    class Meta:
        model = LeaveType
        fields = ["id", "name", "max_days", "is_active"]


class LeaveSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(
        source="employee.get_full_name", read_only=True
    )
    leave_type_name = serializers.CharField(source="leave_type.name", read_only=True)
    institution_name = serializers.CharField(
        source="employee.institution.name", read_only=True
    )
    leave_duration = serializers.SerializerMethodField()

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
        ]

    def get_leave_duration(self, obj):
        return calculate_working_days(obj.start_date, obj.end_date)

    def get_employee_name(self, obj):
        full_name = obj.employee.first_name + " " + obj.employee.last_name

        return full_name.strip() if full_name.strip() else obj.employee.email

    def get_leave_type_name(self, obj):
        return obj.leave_type.name if obj.leave_type else None

    def validate(self, data):
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        leave_type = data.get("leave_type")
        document = data.get("document")

        if start_date and end_date:
            if end_date < start_date:
                raise serializers.ValidationError(
                    {"end_date": "end_date cannot be before start_date."}
                )

        if leave_type and not leave_type.is_active:
            raise serializers.ValidationError(
                {"leave_type": f"'{leave_type.name}' is currently inactive."}
            )

        if leave_type and leave_type.requires_document and not document:
            raise serializers.ValidationError(
                {"document": f"A document is required for '{leave_type.name}'."}
            )

        if start_date and end_date and leave_type:
            duration = (end_date - start_date).days + 1
            if duration > leave_type.max_days:
                raise serializers.ValidationError(
                    {
                        "end_date": (
                            f"Duration of {duration} days exceeds the maximum "
                            f"of {leave_type.max_days} days for '{leave_type.name}'."
                        )
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
        return value
