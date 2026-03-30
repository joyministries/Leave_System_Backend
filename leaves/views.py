from rest_framework import viewsets, status, filters
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import APIException
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth import authenticate
from django.utils import timezone
from django.db import transaction
from django.db.models import Count, Sum, Max, Q, F
import datetime

from .filters import RoleBasedAccessFilter
from .models import Institution, Employee, LeaveType, Leave, LeaveBalance
from .serializers import (
    InstitutionSerializer,
    EmployeeSerializer,
    EmployeeCreateSerializer,
    EmployeeUpdateSerializer,
    LeaveSerializer,
    LeaveTypeSerializer,
    LeaveBalanceSerializer,
    LeaveSummarySerializer,
    LoginSerializer,
    LeaveStatusUpdateSerializer,
    SetPasswordSerializer,
    PostLoginPasswordSerializer,
)
from .utils import (
    calculate_working_days,
    send_account_creation_email,
    send_password_reset_email,
    leave_request_notification_email,
    leave_request_status_email,
    leave_request_submitted_email,
)
from .permissions import IsAdminRole, IsAdminOrDirector, IsManagerOrHREmployeeOnly
import logging
import traceback

logger = logging.getLogger(__name__)


# =============================================================================
# AUTH VIEWS
# =============================================================================


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        employee = authenticate(
            request,
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
        logger.info(f"Employee {employee.email} logged in.")

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
    Activated by the link in the invitation / password-reset email.
    The link contains a base64-encoded uid and a time-limited token.
    No authentication required — the token IS the credential.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        employee = serializer.save()
        logger.info(f"Employee {employee.email} set their password via email link.")
        return Response(
            {"message": "Password set successfully. You can now log in."},
            status=status.HTTP_200_OK,
        )


class PostLoginPasswordView(APIView):
    """
    Fallback for the rare case where must_reset_password is True but
    the employee is somehow already authenticated (e.g., token from an older
    session that was never invalidated).
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
        serializer.save(employee=request.user)
        return Response({"message": "Password updated successfully."})


class PasswordResetRequestView(APIView):
    """
    Sends a password-reset email.
    Always returns the same message regardless of whether the email exists
    — this prevents user enumeration attacks.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip()
        if not email:
            return Response(
                {"error": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        GENERIC_MSG = {
            "message": (
                "If an account with this email exists you will receive "
                "a password reset link shortly."
            )
        }

        try:
            employee = Employee.objects.get(
                email=email, is_active=True, is_deleted=False
            )
        except Employee.DoesNotExist:
            # Return 200 to avoid user enumeration
            return Response(GENERIC_MSG, status=status.HTTP_200_OK)

        try:
            send_password_reset_email(employee)
            logger.info(f"Password reset email sent to {employee.email}")
        except Exception as exc:
            logger.error(f"Password reset email failed for {employee.email}: {exc}")
            raise APIException("Failed to send reset email. Please try again later.")

        return Response(GENERIC_MSG, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            token = RefreshToken(request.data["refresh"])
            token.blacklist()
            logger.info(f"Employee {request.user.email} logged out.")
            return Response(
                {"message": "Logged out successfully."},
                status=status.HTTP_205_RESET_CONTENT,
            )
        except Exception as exc:
            logger.error(f"Logout error for {request.user.email}: {exc}")
            return Response(
                {"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST
            )


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(EmployeeSerializer(request.user).data)


# =============================================================================
# INSTITUTION VIEWS
# =============================================================================


class InstitutionViewSet(viewsets.ModelViewSet):
    queryset = Institution.objects.all()
    serializer_class = InstitutionSerializer
    permission_classes = [IsAuthenticated, IsAdminOrDirector]
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]

    def create(self, request, *args, **kwargs):
        if Institution.objects.filter(name=request.data.get("name")).exists():
            return Response(
                {"error": "An institution with this name already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().create(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        institution = self.get_object()
        if institution.employees.filter(is_active=True).exists():
            return Response(
                {"error": "Cannot delete an institution that has active employees."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(
        detail=True,
        methods=["get"],
        permission_classes=[IsAuthenticated, IsAdminOrDirector],
    )
    def employees(self, request, pk=None):
        institution = self.get_object()
        employees = institution.employees.filter(is_active=True).select_related(
            "institution"
        )
        return Response(EmployeeSerializer(employees, many=True).data)

    @action(
        detail=True,
        methods=["get"],
        permission_classes=[IsAuthenticated, IsAdminOrDirector],
    )
    def employee_count(self, request, pk=None):
        count = self.get_object().employees.filter(is_active=True).count()
        return Response({"employee_count": count})


# =============================================================================
# EMPLOYEE VIEWS
# =============================================================================


class EmployeeViewSet(viewsets.ModelViewSet):
    queryset = Employee.objects.select_related("institution").filter(is_deleted=False)
    permission_classes = [IsAuthenticated, IsManagerOrHREmployeeOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, RoleBasedAccessFilter]
    filterset_fields = {
        "department": ["exact", "icontains"],
        "position": ["exact", "icontains"],
        "role": ["exact"],
        "institution": ["exact"],
        "is_active": ["exact"],
    }
    search_fields = [
        "email",
        "first_name",
        "last_name",
        "department",
        "position",
        "role",
    ]

    # Consumed by RoleBasedAccessFilter
    institution_lookup_field = "institution"
    employee_lookup_field = "id"

    def get_serializer_class(self):
        if self.action == "create":
            return EmployeeCreateSerializer
        if self.action in ["update", "partial_update"]:
            return EmployeeUpdateSerializer
        return EmployeeSerializer

    def create(self, request, *args, **kwargs):
        """
        Admin creates a new employee.
        The employee receives an invitation email with a secure link to set
        their own password. No plain-text password is ever generated or sent.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            employee = serializer.save()
            logger.info(f"Employee created: {employee.email} (id={employee.id})")

        # Send invitation outside the transaction so a mail failure
        # does not roll back the account creation.
        try:
            send_account_creation_email(employee)
            logger.info(f"Account creation email sent to {employee.email}")
        except Exception as exc:
            logger.error(
                f"Account creation email failed for {employee.email}: {exc}\n"
                f"{traceback.format_exc()}"
            )
            # The account was created. Log the error but return success.
            # Admin can resend via the resend_invite endpoint.

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def destroy(self, request, *args, **kwargs):
        """Soft-delete: mark as deleted and deactivate. Never hard-delete."""
        employee = self.get_object()
        employee.delete()
        return Response(
            {"message": "Employee record removed successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )

    @action(detail=True, methods=["get"])
    def leaves(self, request, pk=None):
        employee = self.get_object()
        leaves = employee.leaves.select_related("leave_type").order_by("-created_at")
        return Response(LeaveSerializer(leaves, many=True).data)

    @action(detail=True, methods=["patch"])
    def toggle_active(self, request, pk=None):
        employee = self.get_object()
        employee.is_active = not employee.is_active
        employee.save(update_fields=["is_active"])
        label = "activated" if employee.is_active else "deactivated"
        logger.info(f"Employee {employee.email} {label}.")
        return Response({"message": f"Employee {employee.email} has been {label}."})

    @action(
        detail=True,
        methods=["post"],
        url_path="resend_invite",
        permission_classes=[IsAuthenticated, IsManagerOrHREmployeeOnly],
    )
    def resend_invite(self, request, pk=None):
        """Resend the account creation email — useful if the link expired."""
        employee = self.get_object()
        if not employee.is_active and not employee.must_reset_password:
            return Response(
                {
                    "error": "Cannot send an account creation email to an active employee who has already set their password."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            send_account_creation_email(employee)
            logger.info(f"Account creation email resent to {employee.email}")
        except Exception as exc:
            logger.error(
                f"Resend invite failed for {employee.email}: {exc}\n{traceback.format_exc()}"
            )
            raise APIException(
                "Failed to resend account creation email. Please try again later."
            )
        return Response({"message": "Account creation email resent successfully."})

    @action(detail=True, methods=["get"], url_path="leave-summary")
    def leave_summary(self, request, pk=None):
        """
        Returns a per-leave-type summary for a specific employee.
        Used by both the employee's own Dashboard and the Admin/HR view.
        """
        employee = self.get_object()
        return Response(_build_leave_summary(employee))


# =============================================================================
# LEAVE TYPE VIEWS
# =============================================================================


class LeaveTypeViewSet(viewsets.ModelViewSet):
    queryset = LeaveType.objects.all()
    serializer_class = LeaveTypeSerializer
    permission_classes = [IsAuthenticated, IsAdminOrDirector]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    search_fields = ["name"]

    filterset_fields = ["is_active", "allowed_month"]
    search_fields = ["name"]

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            return [IsAuthenticated(), IsAdminOrDirector()]
        return [IsAuthenticated()]

    def destroy(self, request, *args, **kwargs):
        leave_type = self.get_object()
        if leave_type.leaves.exists():
            return Response(
                {
                    "error": "Cannot delete a leave type that has existing leave records."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def toggle_active(self, request, pk=None):
        leave_type = self.get_object()
        leave_type.is_active = not leave_type.is_active
        leave_type.save(update_fields=["is_active"])
        state = "activated" if leave_type.is_active else "deactivated"
        return Response(
            {"message": f"Leave type '{leave_type.name}' has been {state}."}
        )


# =============================================================================
# LEAVE VIEWS
# =============================================================================


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class LeaveViewSet(viewsets.ModelViewSet):
    pagination_class = StandardResultsSetPagination
    serializer_class = LeaveSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, RoleBasedAccessFilter]
    filterset_fields = ["employee", "status", "leave_type"]
    search_fields = [
        "leave_type__name",
        "status",
        "employee__email",
        "employee__first_name",
        "employee__last_name",
    ]

    # Consumed by RoleBasedAccessFilter
    institution_lookup_field = "employee__institution"
    employee_lookup_field = "employee"

    queryset = Leave.objects.select_related(
        "employee",
        "leave_type",
        "employee__institution",
    ).all()

    def perform_create(self, serializer):
        """
        Save the leave. If the requested duration exceeds the leave type's
        max_days, the overflow is recorded as extra_unpaid_days.
        The request is ALWAYS accepted — excess days are just marked unpaid.
        """
        leave = serializer.save(employee=self.request.user)
        if leave.duration > leave.leave_type.max_days:
            leave.extra_unpaid_days = leave.duration - leave.leave_type.max_days
            leave.save(update_fields=["extra_unpaid_days"])

        logger.info(
            f"Leave request created: Employee {leave.employee.email}, Type {leave.leave_type.name}, Duration {leave.duration} days (including {leave.extra_unpaid_days} unpaid)"
        )
        leave_request_submitted_email(leave.employee, leave_request=leave)

    def destroy(self, request, *args, **kwargs):
        leave = self.get_object()
        if leave.status not in [Leave.Status.APPROVED, Leave.Status.PENDING]:
            return Response(
                {"error": "Only pending or approved leave requests can be cancelled."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        leave.status = Leave.Status.CANCELLED
        leave.save(update_fields=["status"])
        leave_request_status_email(
            leave.employee, leave_request=leave, email_type="rejection"
        )
        return Response(
            {"message": "Leave request cancelled."}, status=status.HTTP_200_OK
        )

    @action(
        detail=True,
        methods=["post"],
        permission_classes=[IsAuthenticated, IsAdminOrDirector],
    )
    def update_status(self, request, pk=None):
        """Approve or reject a leave request. ADMIN / DIRECTOR only."""
        try:
            leave = self.get_object()

            if leave.status == Leave.Status.REJECTED:
                return Response(
                    {"error": "Cannot update a cancelled or rejected leave request."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = LeaveStatusUpdateSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            new_status = serializer.validated_data["status"]
            admin_remarks = serializer.validated_data.get("admin_remarks", "")

            leave.status = new_status
            if admin_remarks:
                leave.admin_remarks = admin_remarks
            leave.save(update_fields=["status", "admin_remarks"])

            # Update the leave balance when a leave is approved
            if new_status == Leave.Status.APPROVED:
                _update_leave_balance(leave)

            # Safely determine email_type
            email_type = None
            if new_status == Leave.Status.APPROVED:
                email_type = "approval"
            elif new_status == Leave.Status.REJECTED:
                email_type = "rejection"
            elif new_status == Leave.Status.CANCELLED:
                email_type = "cancellation"

            # Wrap email in its own try/except so it doesn't crash the main thread
            if email_type:
                try:
                    leave_request_status_email(
                        leave.employee, leave_request=leave, email_type=email_type
                    )
                except Exception as exc:
                    logger.error(f"Email failed to send: {exc}")

            return Response({"message": f"Leave status updated to {new_status}."})

        except Exception as e:
            # === THE DEBUG TRAP ===
            error_trace = traceback.format_exc()

            # 1. Print a massive, unmissable block in your terminal
            print("\n" + "=" * 50)
            print("🚨 CRITICAL 500 ERROR CAUGHT IN UPDATE_STATUS 🚨")
            print("=" * 50)
            print(error_trace)
            print("=" * 50 + "\n")

            # 2. Send the exact error directly back to your Vite frontend
            return Response(
                {
                    "message": "A server error occurred.",
                    "developer_error": str(e),
                    "traceback": error_trace,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        """Employee cancels their own pending leave."""
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
        leave.save(update_fields=["status"])
        leave_request_notification_email(leave.employee, leave_request=leave)
        leave_request_status_email(
            leave.employee, leave_request=leave, email_type="cancellation"
        )
        return Response({"message": "Leave request cancelled."})

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def pending_leaves(self, request):
        qs = self.filter_queryset(self.get_queryset()).filter(
            status=Leave.Status.PENDING
        )
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(LeaveSerializer(page, many=True).data)
        return Response(LeaveSerializer(qs, many=True).data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def by_employee(self, request):
        qs = self.filter_queryset(self.get_queryset())
        employee_id = request.query_params.get("employee_id")
        time_filter = request.query_params.get("time_filter", "all")

        if employee_id:
            qs = qs.filter(employee_id=employee_id)

        if time_filter == "past_month":
            qs = qs.filter(
                start_date__gte=(timezone.now() - datetime.timedelta(days=30)).date()
            )

        qs = qs.order_by("-start_date", "-created_at")
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(LeaveSerializer(page, many=True).data)
        return Response(LeaveSerializer(qs, many=True).data)

    @action(detail=False, methods=["get"])
    def reports(self, request):
        qs = self.filter_queryset(self.get_queryset())
        return Response(
            {
                "total_applications": qs.count(),
                "approved": qs.filter(status=Leave.Status.APPROVED).count(),
                "pending": qs.filter(status=Leave.Status.PENDING).count(),
                "rejected": qs.filter(status=Leave.Status.REJECTED).count(),
            }
        )

    @action(detail=False, methods=["get"], url_path="department-reports")
    def departmental_reports(self, request):
        """
        Grouped by institution → department → list of leave records.
        Uses a single queryset with select_related — no N+1 queries.
        """
        qs = self.filter_queryset(self.get_queryset()).select_related(
            "employee__institution", "leave_type"
        )
        report = {}
        for leave in qs:
            inst = (
                leave.employee.institution.name
                if leave.employee.institution
                else "No Institution"
            )
            dept = leave.employee.department or "General"
            report.setdefault(inst, {}).setdefault(dept, []).append(
                {
                    "employee": f"{leave.employee.first_name} {leave.employee.last_name}".strip()
                    or leave.employee.email,
                    "leave_type_name": leave.leave_type.name,
                    "status": leave.status,
                    "start_date": str(leave.start_date),
                    "end_date": str(leave.end_date),
                    "duration": calculate_working_days(
                        leave.start_date, leave.end_date
                    ),
                    "extra_unpaid_days": leave.extra_unpaid_days,
                }
            )
        return Response(report)

    @action(
        detail=False,
        methods=["get"],
        url_path="my-summary",
        permission_classes=[IsAuthenticated],
    )
    def my_leave_summary(self, request):
        """
        Returns the leave summary table for the currently authenticated employee.
        Used by the employee Dashboard.
        """
        summary_data = _build_leave_summary(request.user)
        serializer = LeaveSummarySerializer(summary_data, many=True)
        return Response(serializer.data)


# =============================================================================
# HELPERS
# =============================================================================


def _build_leave_summary(employee):
    """
    Build a list of leave summary rows for the given employee.
    Ensures ALL active leave types are shown, even if the employee has never applied.

    Uses exactly 5 queries with O(1) database hits regardless of leave history.
    """
    current_year = datetime.date.today().year
    today = datetime.date.today()

    # Query 1: Base Query — Get ALL active leave types
    active_leave_types = LeaveType.objects.filter(is_active=True).order_by("name")

    # Query 2: Get Balances for the current year
    balances = {
        b.leave_type_id: b
        for b in LeaveBalance.objects.filter(employee=employee, year=current_year)
    }

    # Query 3: Get Application Aggregates
    leave_agg = {
        agg["leave_type_id"]: agg
        for agg in Leave.objects.filter(employee=employee)
        .values("leave_type_id")
        .annotate(
            total_applications=Count("id"),
            last_start_date=Max("start_date"),
            last_end_date=Max("end_date"),
        )
        .order_by()
    }

    # Query 4: Get the latest status per leave type
    # By ordering by -start_date, the first one we see per type is the latest.
    last_statuses = {}
    for leave in (
        Leave.objects.filter(employee=employee)
        .order_by("leave_type_id", "-start_date")
        .values("leave_type_id", "status")
    ):
        if leave["leave_type_id"] not in last_statuses:
            last_statuses[leave["leave_type_id"]] = leave["status"]

    # Query 5: Get ongoing approved leaves (to determine if leave type is currently active)
    ongoing_leaves = {
        leave["leave_type_id"]: True
        for leave in Leave.objects.filter(
            employee=employee,
            status=Leave.Status.APPROVED,
            start_date__lte=today,
            end_date__gte=today,
        )
        .values("leave_type_id")
        .distinct()
    }

    # Assemble the final rows in Python
    rows = []
    for lt in active_leave_types:
        lt_id = lt.id
        max_days = lt.max_days
        allowed_month = lt.allowed_month

        # Get balance data (default to 0 if the employee hasn't used any yet)
        balance = balances.get(lt_id)
        days_used = float(balance.days_used) if balance else 0.0
        days_remaining = max(0.0, float(max_days) - days_used)

        # Get aggregate data (default to None/0 if no applications exist)
        agg = leave_agg.get(lt_id, {})
        last_start = agg.get("last_start_date")
        last_end = agg.get("last_end_date")
        total_apps = agg.get("total_applications", 0)

        # Calculate duration only if dates exist
        last_dur = (
            calculate_working_days(last_start, last_end)
            if last_start and last_end
            else None
        )

        rows.append(
            {
                "leave_type_id": lt_id,
                "leave_type_name": lt.name,
                "max_days": max_days,
                "allowed_month": allowed_month,
                "days_used": days_used,
                "days_remaining": days_remaining,
                "last_start_date": str(last_start) if last_start else None,
                "last_end_date": str(last_end) if last_end else None,
                "last_duration": last_dur,
                "total_applications": total_apps,
                "is_active": ongoing_leaves.get(lt_id, False),
                "status": last_statuses.get(lt_id),
            }
        )

    return rows


def _update_leave_balance(leave: Leave):
    """
    When a leave is approved, increment the employee's leave balance
    for the leave's year. Only paid days are counted against the balance.
    Creates the balance row if it doesn't exist yet.
    """
    year = leave.start_date.year
    paid = leave.paid_days or 0
    if paid == 0:
        return
    LeaveBalance.objects.get_or_create(
        employee=leave.employee,
        leave_type=leave.leave_type,
        year=year,
        defaults={"days_used": 0},
    )
    # Use F() to avoid race conditions on concurrent approvals
    LeaveBalance.objects.filter(
        employee=leave.employee,
        leave_type=leave.leave_type,
        year=year,
    ).update(days_used=F("days_used") + paid)
