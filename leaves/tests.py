from django.test import TestCase
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import date, timedelta
from unittest.mock import patch
import uuid

from .models import Institution, Employee, LeaveType, Leave


class ByEmployeeLeaveEndpointTestCase(APITestCase):
    """Test cases for the GET /leaves/by_employee/ endpoint"""

    def setUp(self):
        """Set up test data"""
        # Create institutions
        self.institution1 = Institution.objects.create(
            name="Tech Corp", address="123 Tech St"
        )
        self.institution2 = Institution.objects.create(
            name="Finance Inc", address="456 Finance Ave"
        )

        # Create leave types
        self.leave_type = LeaveType.objects.create(
            name="Annual Leave",
            description="Regular annual leave",
            institution=self.institution1,
            max_days_per_year=20,
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
            role=Employee.Role.STAFF,
        )

        self.employee2 = Employee.objects.create_user(
            email="employee2@techcorp.com",
            password="testpass123",
            first_name="Jane",
            last_name="Smith",
            department="Engineering",
            position="Product Manager",
            institution=self.institution1,
            role=Employee.Role.STAFF,
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
            role=Employee.Role.STAFF,
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
            role=Employee.Role.HR,
        )

        self.admin_user = Employee.objects.create_user(
            email="admin@techcorp.com",
            password="testpass123",
            first_name="Admin",
            last_name="User",
            department="Engineering",
            position="Administrator",
            institution=self.institution1,
            role=Employee.Role.ADMIN,
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
            role=Employee.Role.HR,
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

    # =============================================
    # Test: Employee accessing their own leaves
    # =============================================

    def test_employee_see_own_leaves_without_parameter(self):
        """Employee can see their own leaves without providing employee_id"""
        token = self.get_token_for_user(self.employee1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # employee1 has 2 leaves
        self.assertEqual(response.data[0]["id"], str(self.leave1.id))
        self.assertEqual(response.data[1]["id"], str(self.leave2.id))

    def test_employee_parameter_ignored(self):
        """Employee cannot use employee_id parameter to see other employees' leaves"""
        token = self.get_token_for_user(self.employee1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        # Try to view employee2's leaves
        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee2.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should still return employee1's leaves (parameter ignored)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]["id"], str(self.leave1.id))

    def test_employee_unauthenticated(self):
        """Unauthenticated request returns 401"""
        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # =============================================
    # Test: HR/Admin viewing department leaves
    # =============================================

    def test_hr_see_all_department_leaves_without_parameter(self):
        """HR can see all leaves from employees in their department"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # HR is in Engineering department, should see leaves from employee1, employee2, but not employee3
        self.assertEqual(
            len(response.data), 3
        )  # leaves from employee1 (2) + employee2 (1)
        leave_ids = [str(leave["id"]) for leave in response.data]
        self.assertIn(str(self.leave1.id), leave_ids)
        self.assertIn(str(self.leave2.id), leave_ids)
        self.assertIn(str(self.leave3.id), leave_ids)
        self.assertNotIn(str(self.leave4.id), leave_ids)

    def test_admin_see_all_department_leaves_without_parameter(self):
        """Admin can see all leaves from employees in their department"""
        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)

    # =============================================
    # Test: HR/Admin filtering by employee_id
    # =============================================

    def test_hr_filter_by_employee_in_same_department(self):
        """HR can filter leaves by employee_id if same department"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee1.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]["id"], str(self.leave1.id))
        self.assertEqual(response.data[1]["id"], str(self.leave2.id))

    def test_hr_filter_by_employee_different_department_forbidden(self):
        """HR cannot filter by employee outside their department"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        # HR in Engineering trying to view employee3 (Sales department)
        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee3.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("institution and department", response.data["error"])

    def test_hr_filter_by_nonexistent_employee(self):
        """HR filtering by non-existent employee returns 404"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        fake_id = uuid.uuid4()
        response = self.client.get(f"/api/leaves/by_employee/?employee_id={fake_id}")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("not found", response.data["error"])

    def test_admin_filter_by_employee_in_same_department(self):
        """Admin can filter leaves by employee_id if same department"""
        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee2.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], str(self.leave3.id))

    # =============================================
    # Test: Cross-institution access
    # =============================================

    def test_hr_different_institution_cannot_see_leaves(self):
        """HR from different institution cannot see leaves"""
        token = self.get_token_for_user(self.hr_other_institution)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)  # No leaves from their institution

    def test_hr_different_institution_cannot_access_employee(self):
        """HR from different institution cannot access specific employee"""
        token = self.get_token_for_user(self.hr_other_institution)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee1.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # =============================================
    # Test: Response format and content
    # =============================================

    def test_response_includes_all_leave_fields(self):
        """Response includes all required leave fields"""
        token = self.get_token_for_user(self.employee1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/leaves/by_employee/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        leave_data = response.data[0]

        # Verify required fields exist
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

    def test_response_is_list(self):
        """Response is always a list, even for single employee"""
        token = self.get_token_for_user(self.hr_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(
            f"/api/leaves/by_employee/?employee_id={self.employee1.id}"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)
        self.assertGreater(len(response.data), 0)


class EmployeeCreationEmailFlowTests(APITestCase):
    """Tests for employee creation and welcome email transactional behavior."""

    def setUp(self):
        self.client = APIClient()

        # Create an institution and an admin user who can create employees
        self.institution = Institution.objects.create(
            name="Test Institution", address="123 Test St"
        )

        self.admin_user = Employee.objects.create_user(
            email="admin@test.com",
            password="adminpass123",
            first_name="Admin",
            last_name="User",
            department="HR",
            position="Administrator",
            institution=self.institution,
            role=Employee.Role.ADMIN,
        )

    def get_token_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_employee_created_even_if_welcome_email_fails(self):
        """If welcome email fails, the employee should still be persisted."""

        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        payload = {
            "email": "new.employee@test.com",
            "first_name": "New",
            "last_name": "Employee",
            "department": "Engineering",
            "position": "Developer",
            "role": Employee.Role.STAFF,
            "institution": str(self.institution.id),
            "phone_number": "1234567890",
        }

        with patch(
            "leaves.views.send_welcome_email", side_effect=Exception("SMTP error")
        ):
            response = self.client.post("/api/employees/", payload, format="json")

        # Creation should still succeed with 201
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Ensure the employee was created even though email failed
        self.assertTrue(Employee.objects.filter(email="new.employee@test.com").exists())

    def test_employee_creation_succeeds_when_welcome_email_succeeds(self):
        """On successful email send, employee should be created normally."""

        token = self.get_token_for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        payload = {
            "email": "success.employee@test.com",
            "first_name": "Success",
            "last_name": "Employee",
            "department": "Engineering",
            "position": "Developer",
            "role": Employee.Role.STAFF,
            "institution": str(self.institution.id),
            "phone_number": "1234567890",
        }

        with patch("leaves.views.send_welcome_email") as mock_send:
            response = self.client.post("/api/employees/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            Employee.objects.filter(email="success.employee@test.com").exists()
        )
        mock_send.assert_called_once()
