from rest_framework.permissions import BasePermission
from .models import Role


class HasAction(BasePermission):
    """
    Generic action-based permission. Build a bound version with `.action("leave.approve")`
    and use it in permission_classes — no new class needed per action.

        permission_classes = [IsAuthenticated, HasAction.action("leave.approve")]
    """

    action_code = None

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if self.action_code is None:
            return True
        return user.has_permission(self.action_code)

    @classmethod
    def action(cls, code: str):
        return type(f"HasAction_{code.replace('.', '_')}", (cls,), {"action_code": code})


class HasAnyAction(BasePermission):
    """Passes if the user holds ANY of the given codes. Use via .any_of(...)."""

    action_codes = ()

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated or not user.role:
            return False
        return user.role.permissions.filter(code__in=self.action_codes).exists()

    @classmethod
    def any_of(cls, *codes):
        return type("HasAnyAction_", (cls,), {"action_codes": codes})


class InInstitutionScope(BasePermission):
    """
    Object-level check driven by the user's role.data_scope:
      GLOBAL      -> always passes
      INSTITUTION -> passes only if the object's institution matches the user's
      OWN         -> passes only if the object belongs to (or is) the user
    Works for both Employee objects and anything with an `.employee` or `.institution` attr.
    """

    def has_object_permission(self, request, view, obj):
        user = request.user
        role = getattr(user, "role", None)
        if not role:
            return False

        if role.data_scope == Role.DataScope.GLOBAL:
            return True

        target_institution = getattr(obj, "institution", None)
        if target_institution is None:
            employee = getattr(obj, "employee", None)
            target_institution = getattr(employee, "institution", None)

        if role.data_scope == Role.DataScope.INSTITUTION:
            return bool(user.institution_id) and target_institution == user.institution

        # OWN
        target_employee = obj if hasattr(obj, "role") else getattr(obj, "employee", None)
        return target_employee == user
