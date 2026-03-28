from rest_framework import viewsets, status, filters
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import APIException
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth import authenticate
from django.utils import timezone
import datetime
from .filters import RoleBasedAccessFilter
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
    send_account_creation_email,
    send_password_reset_email,
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
# (Auth views remain unchanged as they do not query lists of records)

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
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not getattr(request.user, "must_reset_password", False):
            return Response(
                {"message": "Password reset not required for this account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = PostLoginPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(employee=request.user)
        return Response(
            {"message": "Password has been updated successfully."},
            status=status.HTTP_200_OK,
        )

class PasswordResetRequestView(APIView):
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
            return Response(
                {
                    "message": "If an account exists with this email, you will receive a password reset link."
                },
                status=200,
            )

        try:
            send_password_reset_email(employee)
            logger.info(f"Password reset email sent to {employee.email}")
        except Exception as e:
            logger.error(
                f"Failed to send password reset email to {employee.email}: {e}"
            )
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

    def create(self, request, *args, **kwargs):
        name = request.data.get("name")
        if Institution.objects.filter(name=name).exists():
            return Response(
                {"error": "Institution with this name already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().create(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
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
        institution = self.get_object()
        employees = institution.employees.filter(is_active=True)
        serializer = EmployeeSerializer(employees, many=True)
        return Response(serializer.data)

    @action(
        detail=True, methods=["get"], permission_classes=[IsAuthenticated, IsAdminOrHR]
    )
    def employee_count(self, request, pk=None):
        institution = self.get_object()
        count = institution.employees.filter(is_active=True).count()
        return Response({"employee_count": count})

    @action(detail=True, methods=["post"])
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
    # Relaxed permission to allow the filter backend to do the heavy lifting safely
    permission_classes = [IsAuthenticated] 
    
    # 1. ADD THE CENTRALIZED FILTER HERE
    filter_backends = [filters.SearchFilter, RoleBasedAccessFilter]
    search_fields = [
        "email",
        "first_name",
        "last_name",
        "department",
        "position",
        "role",
    ]
    
    # 2. DEFINE THE LOOKUP FIELDS FOR THE FILTER TO READ
    institution_lookup_field = 'institution'
    employee_lookup_field = 'id'

    # (get_queryset is completely deleted because the filter backend handles it all!)

    def get_serializer_class(self):
        if self.action == "create":
            return EmployeeCreateSerializer
        elif self.action in ["update", "partial_update"]:
            return EmployeeUpdateSerializer
        return EmployeeSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            employee = serializer.save()
            logger.info(
                f"Employee {employee.email} created successfully with ID {employee.id}."
            )

        try:
            logger.info("Attempting to send welcome email...")
            send_account_creation_email(employee)
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
        employee = self.get_object()
        employee.is_deleted = True
        employee.is_active = False
        employee.save()
        return Response(
            {"message": "Employee record removed successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )

    @action(detail=True, methods=["get"])
    def leaves(self, request, pk=None):
        employee = self.get_object()
        leaves = employee.leaves.all()
        serializer = LeaveSerializer(leaves, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["patch"])
    def toggle_active(self, request, pk=None):
        """
        Toggle active status instead of hard deleting, we set is_active to False and is_deleted to True.
        """
        employee = self.get_object()
        employee.is_active = not employee.is_active
        employee.save()
        status_label = 'activated' if employee.is_active else 'deactivated'
        logger.info(f"Employee {employee.email} has been {status_label}.")

        return Response(
            {
                "message": f"Employee {employee.email} has been {status_label}."
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, 
            methods=["post"], 
            url_path="resend_welcome_email",
            permission_classes=[IsAuthenticated, IsAdminOrHR])
    def resend_email(self, request, pk=None):
        employee = self.get_object()
        if not employee.is_active:
            return Response(
                {"error": "Cannot send email to an inactive employee."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            send_account_creation_email(employee)
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
        if self.action in [
            "create",
            "update",
            "partial_update",
            "destroy",
        ]:
            return [IsAuthenticated(), IsAdminOrHR()]
        return [IsAuthenticated()]

    def destroy(self, request, *args, **kwargs):
        leave_type = self.get_object()
        if leave_type.leaves.exists():
            return Response(
                {
                    "error": "Cannot delete leave type that is associated with existing leave requests."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def toggle_active(self, request, pk=None):
        leave_type = self.get_object()
        leave_type.is_active = not leave_type.is_active
        leave_type.save()

        return Response(
            {
                "message": f"Leave type {leave_type.name} has been {'activated' if leave_type.is_active else 'deactivated'} successfully."
            },
            status=status.HTTP_200_OK,
        )


# =============================
# LEAVE VIEWS
# =============================

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100

class LeaveViewSet(viewsets.ModelViewSet):
    pagination_class = StandardResultsSetPagination
    serializer_class = LeaveSerializer
    permission_classes = [IsAuthenticated]
    
    # 1. ADD THE CENTRALIZED FILTER HERE
    filter_backends = [filters.SearchFilter, RoleBasedAccessFilter]
    search_fields = [
        "leave_type__name",
        "status",
        "employee__email",
        "employee__first_name",
        "employee__last_name",
    ]

    # 2. DEFINE THE LOOKUP FIELDS
    institution_lookup_field = 'employee__institution'
    employee_lookup_field = 'employee'

    # The base queryset has no security logic attached to it, just efficient joins
    queryset = Leave.objects.select_related(
        "employee",
        "leave_type",
        "employee__institution"
    ).all()

    # (get_queryset is completely deleted because the filter backend handles it all!)

    def perform_create(self, serializer):
        serializer.save(employee=self.request.user)

    def destroy(self, request, *args, **kwargs):
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
        methods=["post"],
        permission_classes=[IsAuthenticated],
    )
    def update_status(self, request, pk=None):
        # get_object() automatically applies the RoleBasedAccessFilter!
        # If an HR tries to access a leave outside their branch, this throws a 404 automatically.
        leave = self.get_object()

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

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
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
        detail=False, methods=["get"], permission_classes=[IsAuthenticated]
    )
    def pending_leaves(self, request):
        # Uses the filter to securely grab only what they are allowed to see
        pending_leaves = self.filter_queryset(self.get_queryset()).filter(
            status=Leave.Status.PENDING
        )
        serializer = LeaveSerializer(pending_leaves, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def by_employee(self, request):
        # 1. This ONE line securely handles all Admin/HR/Manager/Employee rules
        employee_leaves = self.filter_queryset(self.get_queryset())

        time_filter = request.query_params.get("time_filter", "all")
        employee_id = request.query_params.get("employee_id")

        if employee_id:
            employee_leaves = employee_leaves.filter(employee_id=employee_id)

        if time_filter == "past_month":
            thirty_days_ago = timezone.now() - datetime.timedelta(days=30)
            employee_leaves = employee_leaves.filter(start_date__gte=thirty_days_ago)

        employee_leaves = employee_leaves.order_by("-start_date", "-id")

        page = self.paginate_queryset(employee_leaves)
        if page is not None:
            serializer = LeaveSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = LeaveSerializer(employee_leaves, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def statistics(self, request):
        # Securely grabs the user's specific allowed slice of the database
        queryset = self.filter_queryset(self.get_queryset())

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