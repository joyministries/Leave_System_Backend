from django.test import TestCase
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import date, timedelta
from unittest.mock import patch
import uuid
from django.core.management import call_command

from .models import Institution, Employee, LeaveType, Leave, LeaveBalance, Notification, Permission, Role, InstitutionSettings


class ByEmployeeLeaveEndpointTestCase(APITestCase):
    """Test cases for the GET /leaves/by_employee/ endpoint"""

    def setUp(self):
        """Set up test data"""
        call_command("seed_rbac")
        self.staff_role = Role.objects.get(name="STAFF", institution=None)
        self.hr_role = Role.objects.get(name="HR", institution=None)
        self.admin_role = Role.objects.get(name="ADMIN", institution=None)

        # Create institutions
        self.institution1 = Institution.objects.create(name="Tech Corp")
        self.institution2 = Institution.objects.create(name="Finance Inc")

        # Create leave types
        self.leave_type = LeaveType.objects.create(
            name="Annual Leave",
            max_days=20,
        )

        # Create employees in institution1, department A
        self.employee1 = Employee.objects.create_user(
            email="employee1@techcorp.com",
            password="testpass123",
            first_name="John",
            last_name="Doe",
            department="Engineering",
            position="Software Engineer",
            institution=self.institution1,
            role=self.staff_role,
        )

        self.employee2 = Employee.objects.create_user(
            email="employee2@techcorp.com",
            password="testpass123",
            first_name="Jane",
            last_name="Smith",
            department="Engineering",
            position="Product Manager",
            institution=self.institution1,
            role=self.staff_role,
        )

        # Create employee in different department
        self.employee3 = Employee.objects.create_user(
            email="employee3@techcorp.com",
            password="testpass123",
            first_name="Bob",
            last_name="Johnson",
            department="Sales",
            position="Sales Manager",
            institution=self.institution1,
            role=self.staff_role,
        )

        # Create HR/Admin users
        self.hr_user = Employee.objects.create_user(
            email="hr@techcorp.com",
            password="testpass123",
            first_name="Alice",
            last_name="HR",
            department="Engineering",
            position="HR Manager",
            institution=self.institution1,
            role=self.hr_role,
        )

        self.admin_user = Employee.objects.create_user(
            email="admin@techcorp.com",
            password="testpass123",
            first_name="Admin",
            last_name="User",
            department="Engineering",
            position="Administrator",
            institution=self.institution1,
            role=self.admin_role,
        )

        # Create HR from different institution
        self.hr_other_institution = Employee.objects.create_user(
            email="hr@finance.com",
            password="testpass123",
            first_name="Charlie",
            last_name="Finance",
            department="HR",
            position="HR Manager",
            institution=self.institution2,
            role=self.hr_role,
        )

        # Create leaves for employee1
        self.leave1 = Leave.objects.create(
            employee=self.employee1,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=1),
            end_date=date.today() + timedelta(days=5),
            reason="Vacation",
            status=Leave.Status.PENDING,
        )

        self.leave2 = Leave.objects.create(
            employee=self.employee1,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=10),
            end_date=date.today() + timedelta(days=12),
            reason="Personal",
            status=Leave.Status.APPROVED,
        )

        # Create leaves for employee2
        self.leave3 = Leave.objects.create(
            employee=self.employee2,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=15),
            end_date=date.today() + timedelta(days=18),
            reason="Medical",
            status=Leave.Status.PENDING,
        )

        # Create leave for employee3 (different department)
        self.leave4 = Leave.objects.create(
            employee=self.employee3,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=20),
            end_date=date.today() + timedelta(days=22),
            reason="Conference",
            status=Leave.Status.APPROVED,
        )

        self.client = APIClient()

    def get_token_for_user(self, user):
        """Helper method to get JWT token for a user"""
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def _get_results(self, response):
        if isinstance(response.data, dict) and "results" in response.data:
            return response.data["results"]
        return response.data

    # =============================================
    # Test: Employee accessing their own leaves
    # =============================================

    def test_employee_see_own_leaves_without_parameter(self):
        """Employee can see their own leaves without providing employee_id"""
        token = self.get_token_for_user(self.employee1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 2)  # employee1 has 2 leaves

    def test_employee_parameter_ignored(self):
        """Employee cannot see other employees' leaves by passing employee_id parameter"""
        token = self.get_token_for_user(self.employee1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        # Try to view employee2's leaves
        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee2.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        # Role-scoped queryset prevents seeing employee2's leaves
        self.assertEqual(len(results), 0)

    def test_employee_unauthenticated(self):
        """Unauthenticated request returns 401"""
        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # =============================================
    # Test: HR/Admin viewing institution leaves
    # =============================================

    def test_hr_see_all_institution_leaves_without_parameter(self):
        """HR can see all leaves from employees in their institution"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 4)

    def test_admin_see_all_leaves_without_parameter(self):
        """Admin has global access and can see leaves across system"""
        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 4)

    # =============================================
    # Test: HR/Admin filtering by employee_id
    # =============================================

    def test_hr_filter_by_employee_in_same_institution(self):
        """HR can filter leaves by employee_id in same institution"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee1.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 2)

    def test_hr_filter_by_nonexistent_employee(self):
        """HR filtering by non-existent employee returns empty list"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        fake_id = uuid.uuid4()
        response = self.client.get(f"/api/leaves/by_employee/?employee_id={fake_id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 0)

    # =============================================
    # Test: Cross-institution access
    # =============================================

    def test_hr_different_institution_cannot_see_leaves(self):
        """HR from different institution cannot see leaves from another institution"""
        token = self.get_token_for_user(self.hr_other_institution)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 0)

    def test_hr_different_institution_cannot_access_employee(self):
        """HR from institution B cannot see leaves of employee in institution A"""
        token = self.get_token_for_user(self.hr_other_institution)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee1.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        self.assertEqual(len(results), 0)

    # =============================================
    # Test: Response format and content
    # =============================================

    def test_response_includes_all_leave_fields(self):
        """Response includes all required leave fields"""
        token = self.get_token_for_user(self.employee1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = self._get_results(response)
        leave_data = results[0]

        required_fields = [
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
        for field in required_fields:
            self.assertIn(field, leave_data, f"Missing field: {field}")


class EmployeeCreationEmailFlowTests(APITestCase):
    """Tests for employee creation and account creation email transactional behavior."""

    def setUp(self):
        call_command("seed_rbac")
        self.staff_role = Role.objects.get(name="STAFF", institution=None)
        self.admin_role = Role.objects.get(name="ADMIN", institution=None)
        self.client = APIClient()

        self.institution = Institution.objects.create(name="Test Institution")

        self.admin_user = Employee.objects.create_user(
            email="admin@test.com",
            password="adminpass123",
            first_name="Admin",
            last_name="User",
            department="HR",
            position="Administrator",
            institution=self.institution,
            role=self.admin_role,
        )

    def get_token_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_employee_created_even_if_email_fails(self):
        """If account creation email fails, the employee should still be persisted."""

        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        payload = {
            "email": "new.employee@test.com",
            "first_name": "New",
            "last_name": "Employee",
            "department": "Engineering",
            "position": "Developer",
            "role": str(self.staff_role.id),
            "institution": str(self.institution.id),
            "phone_number": "1234567890",
        }

        with patch(
            "leaves.views.send_account_creation_email", side_effect=Exception("SMTP error")
        ):
            response = self.client.post("/api/employees/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Employee.objects.filter(email="new.employee@test.com").exists())

    def test_employee_creation_succeeds_when_email_succeeds(self):
        """On successful email send, employee should be created normally."""

        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        payload = {
            "email": "success.employee@test.com",
            "first_name": "Success",
            "last_name": "Employee",
            "department": "Engineering",
            "position": "Developer",
            "role": str(self.staff_role.id),
            "institution": str(self.institution.id),
            "phone_number": "1234567890",
        }

        with patch("leaves.views.send_account_creation_email") as mock_send:
            response = self.client.post("/api/employees/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            Employee.objects.filter(email="success.employee@test.com").exists()
        )
        mock_send.assert_called_once()


class PreMigrationGateAndNotificationTests(APITestCase):
    """Tests for Notification engine and pre-migration bug fixes."""

    def setUp(self):
        call_command("seed_rbac")
        self.staff_role = Role.objects.get(name="STAFF", institution=None)
        self.hr_role = Role.objects.get(name="HR", institution=None)

        self.institution_a = Institution.objects.create(name="Institution A")
        self.institution_b = Institution.objects.create(name="Institution B")

        self.leave_type = LeaveType.objects.create(name="Annual Leave", max_days=20)

        self.emp_a = Employee.objects.create_user(
            email="emp.a@insta.com",
            password="testpass123",
            first_name="Emp",
            last_name="A",
            department="Engineering",
            position="Developer",
            institution=self.institution_a,
            role=self.staff_role,
        )

        self.emp_b = Employee.objects.create_user(
            email="emp.b@instb.com",
            password="testpass123",
            first_name="Emp",
            last_name="B",
            department="Finance",
            position="Accountant",
            institution=self.institution_b,
            role=self.staff_role,
        )

        self.hr_a = Employee.objects.create_user(
            email="hr.a@insta.com",
            password="testpass123",
            first_name="HR",
            last_name="A",
            department="HR",
            position="HR Officer",
            institution=self.institution_a,
            role=self.hr_role,
        )

        self.client = APIClient()

    def get_token_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_hr_sees_only_own_institution_leaves(self):
        """HR user in Institution A sees leaves from Institution A employees, not Institution B."""
        Leave.objects.create(
            employee=self.emp_a,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=1),
            end_date=date.today() + timedelta(days=3),
            reason="Leave A",
        )
        Leave.objects.create(
            employee=self.emp_b,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=1),
            end_date=date.today() + timedelta(days=3),
            reason="Leave B",
        )

        token = self.get_token_for_user(self.hr_a)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data.get("results", response.data)
        self.assertEqual(len(results), 1)
        self.assertEqual(str(results[0]["employee"]), str(self.emp_a.id))

    def test_extra_unpaid_days_calculated_from_days_remaining(self):
        """Employee with days_remaining < duration gets extra_unpaid_days based on remaining balance."""
        current_year = date.today().year
        # max_days is 20. Employee has already used 15 days, so days_remaining is 5.
        LeaveBalance.objects.create(
            employee=self.emp_a,
            leave_type=self.leave_type,
            year=current_year,
            days_used=15,
        )

        token = self.get_token_for_user(self.emp_a)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        # Request 10 days of leave (which is <= max_days 20, but > remaining 5)
        payload = {
            "leave_type": self.leave_type.id,
            "start_date": str(date.today() + timedelta(days=1)),
            "end_date": str(date.today() + timedelta(days=10)),
            "reason": "Extended Leave",
        }

        response = self.client.post("/api/leaves/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        created_leave = Leave.objects.get(id=response.data["id"])
        # duration is 10 days, remaining was 5, so extra_unpaid_days should be 10 - 5 = 5
        self.assertEqual(created_leave.extra_unpaid_days, 5)

    def test_cancel_does_not_trigger_submission_notification_email(self):
        """cancel() must NOT trigger leave_request_notification_email."""
        leave = Leave.objects.create(
            employee=self.emp_a,
            leave_type=self.leave_type,
            start_date=date.today() + timedelta(days=1),
            end_date=date.today() + timedelta(days=3),
            reason="To be cancelled",
            status=Leave.Status.PENDING,
        )

        token = self.get_token_for_user(self.emp_a)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        with patch("leaves.views.leave_request_notification_email") as mock_admin_notify:
            response = self.client.post(f"/api/leaves/{leave.id}/cancel/")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_admin_notify.assert_not_called()

    def test_notifications_scoped_to_authenticated_user(self):
        """GET /api/notifications/ returns only the authenticated user's own notifications."""
        n1 = Notification.objects.create(
            recipient=self.emp_a,
            notification_type=Notification.NotificationType.LEAVE_APPROVED,
            message="Notice for A",
        )
        n2 = Notification.objects.create(
            recipient=self.emp_b,
            notification_type=Notification.NotificationType.LEAVE_REJECTED,
            message="Notice for B",
        )

        token_a = self.get_token_for_user(self.emp_a)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")

        response = self.client.get("/api/notifications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data.get("results", response.data)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], str(n1.id))

    def test_notification_unread_count_and_mark_all_read(self):
        """GET /api/notifications/unread_count/ and POST /api/notifications/mark_all_read/ work as expected."""
        Notification.objects.create(
            recipient=self.emp_a,
            notification_type=Notification.NotificationType.LEAVE_APPROVED,
            message="Notice 1",
            is_read=False,
        )
        Notification.objects.create(
            recipient=self.emp_a,
            notification_type=Notification.NotificationType.LEAVE_SUBMITTED,
            message="Notice 2",
            is_read=False,
        )

        token_a = self.get_token_for_user(self.emp_a)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_a}")

        # Check unread count
        response = self.client.get("/api/notifications/unread_count/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["unread_count"], 2)

        # Mark all as read
        response = self.client.post("/api/notifications/mark_all_read/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check unread count again
        response = self.client.get("/api/notifications/unread_count/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["unread_count"], 0)


class RbacAndRoleManagementTests(APITestCase):
    """Tests for new RBAC functionality, Role API, system roles protection, and institution scoping."""

    def setUp(self):
        call_command("seed_rbac")
        self.client = APIClient()
        self.institution_a = Institution.objects.create(name="School A")
        self.institution_b = Institution.objects.create(name="School B")

        self.admin_role = Role.objects.get(name="ADMIN", institution=None)
        self.staff_role = Role.objects.get(name="STAFF", institution=None)

        self.admin_user = Employee.objects.create_user(
            email="global.admin@test.com",
            password="adminpass123",
            first_name="Global",
            last_name="Admin",
            department="IT",
            position="Admin",
            institution=self.institution_a,
            role=self.admin_role,
        )

    def get_token_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_cannot_delete_system_role(self):
        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.delete(f"/api/roles/{self.admin_role.id}/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("System roles cannot be deleted", response.data["error"])

    def test_create_and_assign_custom_institution_role(self):
        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        payload = {
            "name": "Custom Department Head",
            "institution": self.institution_a.id,
            "data_scope": "INSTITUTION",
            "permission_codes": ["employee.view", "leave.create"],
        }
        response = self.client.post("/api/roles/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_role_id = response.data["id"]

        custom_role = Role.objects.get(id=new_role_id)
        self.assertEqual(custom_role.institution, self.institution_a)
        self.assertTrue(custom_role.has_permission("leave.create"))
        self.assertFalse(custom_role.has_permission("employee.delete"))
