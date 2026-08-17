from rest_framework import filters
from django.core.exceptions import FieldError
from .models import Role


class RoleBasedAccessFilter(filters.BaseFilterBackend):
    """
    Row-level security driven by the requester's Role.data_scope, not by role name.
    Looks for `institution_lookup_field` / `employee_lookup_field` on the ViewSet, same
    as before.
    """

    def filter_queryset(self, request, queryset, view):
        user = request.user

        try:
            if hasattr(queryset.model, "is_deleted"):
                queryset = queryset.filter(is_deleted=False)
            elif hasattr(queryset.model, "employee"):
                queryset = queryset.filter(employee__is_deleted=False)
        except FieldError:
            pass

        if not user or not user.is_authenticated or not user.role:
            return queryset.none()

        scope = user.role.data_scope

        if scope == Role.DataScope.GLOBAL:
            return queryset

        institution_field = getattr(view, "institution_lookup_field", None)
        employee_field = getattr(view, "employee_lookup_field", None)

        if scope == Role.DataScope.INSTITUTION:
            if user.institution_id and institution_field:
                return queryset.filter(**{institution_field: user.institution})
            return queryset.none()  # fail secure if no institution on the account

        # OWN
        if employee_field:
            return queryset.filter(**{employee_field: user})
        return queryset.none()
