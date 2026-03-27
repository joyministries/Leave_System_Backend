from rest_framework import viewsets, status, filters, generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import APIException
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
import traceback
from django.db import transaction
from .models import Institution, Employee, LeaveType, Leave
from .serializers import (
    InstitutionSerializer,
    EmployeeSerializer,
    EmployeeCreateSerializer,
    EmployeeUpdateSerializer,
    LeaveSerializer,
    LeaveTypeSerializer,
    LoginSerializer,
    LeaveStatusUpdateSerializer,
    SetPasswordSerializer,
    PostLoginPasswordSerializer,
)
from .utils import (
    calculate_working_days,
    send_email,
    send_password_reset_email,
    send_welcome_email,
)
import logging
from .permissions import (
    IsAdminRole,
    IsAdminOrHR,
    IsAdminOrHROfSameInstitutionAndDepartment,
)

logger = logging.getLogger(__name__)

# =============================
# AUTH VIEWS
# =============================


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        employee = authenticate(
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )

        if not employee:
            return Response(
                {"message": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not employee.is_active:
            return Response(
                {
                    "message": "Your account is inactive. Please contact your administrator."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(employee)
        logger.info(f"Employee {employee.email} logged in successfully.")

        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "employee": EmployeeSerializer(employee).data,
                "must_reset_password": employee.must_reset_password,
            }
        )


class SetPassword(APIView):
    """
    Called when employee clicks the set link in their email.
    Validates uid and token, then sets the new password.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        employee = serializer.save()
        logger.info(f"Employee {employee.email} has set their password successfully.")

        return Response(
            {"message": "Password has been set successfully."},
            status=status.HTTP_200_OK,
        )


class PostLoginPasswordView(APIView):
    """
    Endpoint for employees to set a new password after logging in, if they are required to reset their password.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not getattr(request.user, "must_reset_password", False):
            return Response(
                {"message": "Password reset not required for this account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = PostLoginPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        employee = request.user
        employee.set_password(serializer.validated_data["new_password"])
        employee.must_reset_password = (
            False  # Clear the flag after setting new password
        )
        employee.save()

        logger.info(
            f"Employee {employee.email} has updated their password successfully post-login."
        )

        return Response(
            {"message": "Password has been updated successfully."},
            status=status.HTTP_200_OK,
        )


class PasswordResetRequestView(APIView):
    """
    Request a password reset. Sends an email with a reset link to the user.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response(
                {"error": "Email field is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            employee = Employee.objects.get(email=email)
            if not employee.is_active:
                raise Employee.DoesNotExist
        except Employee.DoesNotExist:
            # Don't reveal if email exists or not (security best practice)
            return Response(
                {
                    "message": "If an account exists with this email, you will receive a password reset link."
                },
                status=200,
            )

        if not employee.is_active:
            return Response(
                {
                    "message": "If an account exists with this email, you will receive a password reset link."
                },
                status=status.HTTP_200_OK,
            )
        try:
            # Generate reset token
            from leaves.utils import generate_password_set_link, send_email

            # Send password reset email
            set_link = generate_password_set_link(employee)
            send_email(
                employee.email,
                "Password Reset Request",
                f"Please click the following link to set your password: {set_link}",
            )

            logger.info(f"Password reset email sent to {employee.email}")
        except Exception as e:
            logger.error(
                f"Failed to send password reset email to {employee.email}: {e}"
            )
            # Surface a clear API-level error; no DB changes are made here
            raise APIException(
                "Failed to send password reset email. Please try again later."
            )

        return Response(
            {
                "message": "If an account exists with this email, you will receive a password reset link."
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"Employee {request.user.email} logged out successfully.")
            return Response(
                {"message": "Logged out successfully."},
                status=status.HTTP_205_RESET_CONTENT,
            )
        except Exception as e:
            logger.error(
                f"Error during logout for employee {request.user.email}: {str(e)}"
            )

            return Response(
                {"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST
            )


class MeView(APIView):
    """Endpoint to get the current authenticated employee's profile
    information."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = EmployeeSerializer(request.user)
        return Response(serializer.data)


# =============================
# INSTITUTION VIEWS
# =============================


class InstitutionViewSet(viewsets.ModelViewSet):

    queryset = Institution.objects.all()
    serializer_class = InstitutionSerializer
    permission_classes = [IsAuthenticated, IsAdminRole]
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]

    # check first if the institution exists then return that institution exists
    def create(self, request, *args, **kwargs):
        name = request.data.get("name")
        if Institution.objects.filter(name=name).exists():
            return Response(
                {"error": "Institution with this name already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().create(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Override destroy to prevent deleting institutions with active employees."""
        institution = self.get_object()
        if institution.employees.filter(is_active=True).exists():
            return Response(
                {"error": "Cannot delete institution with active employees."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(
        detail=True, methods=["get"], permission_classes=[IsAuthenticated, IsAdminOrHR]
    )
    def employees(self, request, pk=None):
        """Get all active employees for this institution."""
        institution = self.get_object()
        employees = institution.employees.filter(is_active=True)
        serializer = EmployeeSerializer(employees, many=True)
        return Response(serializer.data)

    @action(
        detail=True, methods=["get"], permission_classes=[IsAuthenticated, IsAdminOrHR]
    )
    def employee_count(self, request, pk=None):
        """Get count of active employees for this institution."""
        institution = self.get_object()
        count = institution.employees.filter(is_active=True).count()
        return Response({"employee_count": count})

    @action(detail=True, methods=["patch"])
    def toggle_active(self, request, pk=None):
        institution = self.get_object()
        institution.is_active = not institution.is_active
        institution.save()

        return Response(
            {
                "message": f"Institution {'activated' if institution.is_active else 'deactivated'} successfully."
            },
            status=status.HTTP_200_OK,
        )


# =============================
# EMPLOYEE VIEWS
# =============================


class EmployeeViewSet(viewsets.ModelViewSet):
    queryset = Employee.objects.select_related("institution").all()
    permission_classes = [IsAuthenticated, IsAdminOrHROfSameInstitutionAndDepartment]
    filter_backends = [filters.SearchFilter]
    lookup_field = "uuid"
    search_fields = [
        "email",
        "first_name",
        "last_name",
        "department",
        "position",
        "role",
    ]

    def get_queryset(self):
        """
        Filter employees based on the requester's institution.
        - Admins/HR/Managers: See all employees in their institution
        - Staff: See no employees (they don't have permission to list anyway)
        """
        user = self.request.user

        if user.role in [Employee.Role.HR, Employee.Role.MANAGER]:
            # Show all employees from the same institution (across all departments)
            return Employee.objects.select_related("institution").filter(
                institution=user.institution
            )
        elif user.role == Employee.Role.ADMIN:
            # Show all employees
            return Employee.objects.all()
        # Staff users can't list employees (permission denied by IsAdminOrHROfSameInstitutionAndDepartment)

        return Employee.objects.select_related("institution").none()

    def get_serializer_class(self):
        """Use different serializers for create/update vs list/retrieve to handle password setting and read-only fields appropriately."""
        if self.action == "create":
            return EmployeeCreateSerializer
        elif self.action in ["update", "partial_update"]:
            return EmployeeUpdateSerializer
        return EmployeeSerializer

    def create(self, request, *args, **kwargs):
        """Create an employee and attempt to send a welcome email.

        The employee is always created if validation passes. If sending the
        welcome email fails, the error is logged but does not prevent creation.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Ensure the creation itself is atomic, but treat email as a
        # best-effort side effect.
        with transaction.atomic():
            employee = serializer.save()
            logger.info(
                f"Employee {employee.email} created successfully with ID {employee.id}."
            )

        try:
            logger.info("Attempting to send welcome email...")
            send_welcome_email(employee)
            logger.info(f"Welcome email sent to new employee: {employee.email}")
        except Exception as e:
            logger.error(
                f"Failed to send welcome email to {employee.email}: {str(e)}\n{traceback.format_exc()}"
            )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def destroy(self, request, *args, **kwargs):
        """Override destroy to perform a soft delete by setting is_active to False."""
        employee = self.get_object()
        employee.is_active = False
        employee.save()
        return Response(
            {"message": "Employee deactivated successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )

    @action(detail=True, methods=["get"])
    def leaves(self, request, pk=None):
        """Get all leave requests for this employee."""
        employee = self.get_object()
        leaves = employee.leaves.all()
        serializer = LeaveSerializer(leaves, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["patch"])
    def toggle_active(self, request, pk=None):
        employee = self.get_object()
        employee.is_active = not employee.is_active
        employee.save()

        return Response(
            {
                "message": f"Employee {'activated' if employee.is_active else 'deactivated'} successfully."
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"], url_path="resend_welcome_email")
    def resend_email(self, request, pk=None):
        """Resend welcome email with password reset link to the employee."""
        employee = self.get_object()
        if not employee.is_active:
            return Response(
                {"error": "Cannot send email to an inactive employee."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            send_welcome_email(employee)
            logger.info(f"Resent welcome email to employee: {employee.email}.")
        except Exception as e:
            logger.error(
                f"Failed to resend welcome email to employee {employee.email}: {str(e)}\n{traceback.format_exc()}"
            )
            raise APIException(
                "Failed to resend welcome email. Please try again later."
            )

        return Response(
            {"message": "Welcome email resent successfully."},
            status=status.HTTP_200_OK,
        )


# =============================
# LEAVE TYPE VIEWS
# =============================


class LeaveTypeViewSet(viewsets.ModelViewSet):
    queryset = LeaveType.objects.all()
    serializer_class = LeaveTypeSerializer
    permission_classes = [IsAuthenticated, IsAdminOrHR]
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]

    def get_permissions(self):
        """Only allow HR and Admin to create/update/delete leave types, but allow all authenticated users to view them."""
        if self.action in [
            "list",
            "retrieve",
            "create",
            "update",
            "partial_update",
            "destroy",
        ]:
            return [IsAuthenticated(), IsAdminOrHR()]
        return [IsAuthenticated()]

    def destroy(self, request, *args, **kwargs):
        """Override destroy to prevent deleting leave types that are associated with existing leave requests."""
        leave_type = self.get_object()
        if leave_type.leaves.exists():
            return Response(
                {
                    "error": "Cannot delete leave type that is associated with existing leave requests."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["patch"])
    def toggle_active(self, request, pk=None):
        leave_type = self.get_object()
        leave_type.is_active = not leave_type.is_active
        leave_type.save()

        return Response(
            {
                "message": f"Leave type {'activated' if leave_type.is_active else 'deactivated'} successfully."
            },
            status=status.HTTP_200_OK,
        )


# =============================
# LEAVE VIEWS
# =============================


class LeaveViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = [
        "leave_type__name",
        "status",
        "employee__email",
        "employee__first_name",
        "employee__last_name",
    ]

    def get_queryset(self):
        """
        Filter leaves based on user role.
        - Employees: Only see their own leaves
        - HR/Admin/Manager: Only see leaves from employees in their institution and department
        """
        user = self.request.user

        if user.role in [Employee.Role.HR, Employee.Role.ADMIN, Employee.Role.MANAGER]:
            # Only show leaves from employees in the same institution and department as the admin/HR/manager
            return Leave.objects.select_related("employee", "leave_type").filter(
                employee__institution=user.institution,
                employee__department=user.department,
            )

        return Leave.objects.select_related("employee", "leave_type").filter(
            employee=user
        )

    def perform_create(self, serializer):
        """Create leave for an employee"""

        serializer.save(employee=self.request.user)

    def destroy(self, request, *args, **kwargs):
        """Override destroy to perform a soft delete by setting status to 'Cancelled'."""
        leave = self.get_object()
        if leave.status in [Leave.Status.APPROVED, Leave.Status.PENDING]:
            leave.status = Leave.Status.CANCELLED
            leave.save()
            return Response(
                {"message": "Leave request cancelled successfully."},
                status=status.HTTP_204_NO_CONTENT,
            )
        return Response(
            {"error": "Only pending or approved leave requests can be cancelled."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(
        detail=True,
        methods=["patch"],
        permission_classes=[IsAuthenticated, IsAdminOrHROfSameInstitutionAndDepartment],
    )
    def update_status(self, request, pk=None):
        """Custom action to update the status of a leave request by HR or Admin from the same institution and department."""
        leave = self.get_object()

        # Check if the requester is from the same institution and department
        if (
            leave.employee.institution != request.user.institution
            or leave.employee.department != request.user.department
        ):
            return Response(
                {
                    "error": "You can only update leaves for employees in your institution and department."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = LeaveStatusUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_status = serializer.validated_data["status"]
        admin_remarks = serializer.validated_data.get("admin_remarks", "")

        if leave.status in [Leave.Status.CANCELLED, Leave.Status.REJECTED]:
            return Response(
                {
                    "error": "Cannot update status of a cancelled or rejected leave request."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        leave.status = new_status
        if admin_remarks:
            leave.admin_remarks = admin_remarks
        leave.save()

        return Response(
            {"message": f"Leave request status updated to {new_status} successfully."},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["patch"])
    def cancel(self, request, pk=None):
        """Action to allow employees to edit their leave request if it's still pending"""
        leave = self.get_object()

        if leave.employee != request.user:
            return Response(
                {"error": "You can only cancel your own leave requests."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if leave.status != Leave.Status.PENDING:
            return Response(
                {"error": "Only pending leave requests can be cancelled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        leave.status = Leave.Status.CANCELLED
        leave.save()

        return Response(
            {"message": "Leave request cancelled successfully."},
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False, methods=["get"], permission_classes=[IsAuthenticated, IsAdminOrHR]
    )
    def pending_leaves(self, request):
        """Get all pending leave requests for HR and Admin."""
        pending_leaves = Leave.objects.select_related("employee", "leave_type").filter(
            status=Leave.Status.PENDING
        )
        serializer = LeaveSerializer(pending_leaves, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def by_employee(self, request):
        """
        Get leave requests filtered by employee.

        - Employees: Always see their own leaves (employee_id parameter ignored)
        - HR/Admin/Managers: See leaves in their institution/department, optionally filtered by employee_id

        Query Parameters:
            employee_id (optional): UUID of the employee to filter by. Only HR/Admin/Managers can use this.
                                  Must be an employee from their own institution and department.

        Returns:
            - 200 OK: List of Leave objects
            - 400 Bad Request: Invalid employee_id format
            - 404 Not Found: Employee not found
            - 403 Forbidden: Employee is outside requester's institution/department (HR/Admin only)
        """
        user = request.user
        employee_id = request.query_params.get("employee_id")

        # For regular employees, always return their own leaves
        if user.role not in [
            Employee.Role.HR,
            Employee.Role.ADMIN,
            Employee.Role.MANAGER,
        ]:
            employee_leaves = Leave.objects.select_related(
                "leave_type", "employee"
            ).filter(employee=user)
            serializer = LeaveSerializer(employee_leaves, many=True)
            return Response(serializer.data)

        # For HR/Admin/Managers
        if employee_id:
            # Validate that the employee exists
            try:
                target_employee = Employee.objects.get(id=employee_id)
            except Employee.DoesNotExist:
                return Response(
                    {"error": f"Employee with ID '{employee_id}' not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Check if target employee is in the same institution and department
            if (
                target_employee.institution != user.institution
                or target_employee.department != user.department
            ):
                return Response(
                    {
                        "error": "You can only view leaves for employees in your institution and department."
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Return leaves for the specific employee
            employee_leaves = Leave.objects.select_related(
                "leave_type", "employee"
            ).filter(employee=target_employee)
        else:
            # Return all leaves from employees in the same institution and department
            employee_leaves = Leave.objects.select_related(
                "leave_type", "employee"
            ).filter(
                employee__institution=user.institution,
                employee__department=user.department,
            )

        serializer = LeaveSerializer(employee_leaves, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def statistics(self, request):
        """
        Get statistics about leave requests.
        - Employees see their own statistics
        - HR/Admin/Managers see statistics for their institution and department
        """
        user = self.request.user
        queryset = self.get_queryset()

        total_leaves = queryset.count()
        approved_leaves = queryset.filter(status=Leave.Status.APPROVED).count()
        rejected_leaves = queryset.filter(status=Leave.Status.REJECTED).count()
        pending_leaves = queryset.filter(status=Leave.Status.PENDING).count()
        cancelled_leaves = queryset.filter(status=Leave.Status.CANCELLED).count()

        statistics = {
            "total_leaves": total_leaves,
            "approved_leaves": approved_leaves,
            "rejected_leaves": rejected_leaves,
            "pending_leaves": pending_leaves,
            "cancelled_leaves": cancelled_leaves,
            "status_breakdown": {
                "APPROVED": approved_leaves,
                "REJECTED": rejected_leaves,
                "PENDING": pending_leaves,
                "CANCELLED": cancelled_leaves,
            },
        }

        return Response({"statistics": statistics}, status=status.HTTP_200_OK)
