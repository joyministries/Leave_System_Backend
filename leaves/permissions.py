from rest_framework.permissions import BasePermission
from .models import Employee


class IsAdminRole(BasePermission):
    """Only employees with the ADMIN or DIRECTOR role."""

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in [
            "ADMIN",
            "DIRECTOR",
        ]


class IsAdminOrDirector(BasePermission):
    """Employees with ADMIN or DIRECTOR role."""

    def has_permission(self, request, view):
        user = request.user

        if not user.is_authenticated:
            return False

        role = getattr(user, "role", None)

        return role in ["ADMIN", "DIRECTOR"]


class IsManagerOrHREmployeeOnly(BasePermission):
    """Manager/HR can only view and add employees, not edit/delete."""

    def has_permission(self, request, view):
        user = request.user

        if not user.is_authenticated:
            return False

        role = getattr(user, "role", None)

        # Allow view (GET) and create (POST) only
        if request.method in ["GET", "POST"]:
            return role in ["MANAGER", "HR", "ADMIN", "DIRECTOR"]

        # Deny all other methods for Manager/HR
        if role in ["MANAGER", "HR"]:
            return False

        # Allow for Admin/Director
        return role in ["ADMIN", "DIRECTOR"]


class IsAdminOrHROfSameInstitutionAndDepartment(BasePermission):
    """
    Permission class to ensure that HR/Admin/Manager can only manage employees
    and leave requests from their own institution and department.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False
        role = getattr(user, "role", None)
        return role in ["ADMIN", "DIRECTOR", "HR", "MANAGER"]

    def has_object_permission(self, request, view, obj):
        """
        Check if the admin/HR/manager has access to the object based on institution and department.
        Works for both Employee and Leave objects.
        """
        user = request.user

        if getattr(user, "role", None) in ["ADMIN", "DIRECTOR"]:
            return True  # Admins and Directors have access to all objects

        # Get the institution and department of the requester
        requester_institution = request.user.institution
        requester_department = request.user.department

        # Handle Leave objects (need to check employee's institution/department)
        if hasattr(obj, "employee"):
            target_institution = obj.employee.institution
            target_department = obj.employee.department
        # Handle Employee objects directly
        else:
            target_institution = obj.institution
            target_department = obj.department

        # Check if requester's institution and department match target
        return (
            requester_institution == target_institution
            and requester_department == target_department
        )
