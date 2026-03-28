# filters.py
from rest_framework import filters

class RoleBasedAccessFilter(filters.BaseFilterBackend):
    """
    A global filter that enforces Row-Level Security based on Employee Role.
    It looks for `institution_lookup_field` and `employee_lookup_field` 
    on the ViewSet to know how to traverse the database relationships.
    """
    def filter_queryset(self, request, queryset, view):
        user = request.user

        queryset = queryset.filter(is_deleted=False) 
        
        # Bypass filtering if the user isn't authenticated
        if not user or not user.is_authenticated:
            return queryset.none()

        user_role = str(user.role).upper() if user.role else ""

        # 1. ADMIN & MANAGER: Global access, sees everything
        if user_role in ['ADMIN', 'MANAGER']:
            return queryset

        # Get the field names specific to the current ViewSet's model
        institution_field = getattr(view, 'institution_lookup_field', None)
        employee_field = getattr(view, 'employee_lookup_field', None)

        # 2. HR: Localized access to their institution
        if user_role in ['HR']:
            if user.institution and institution_field:
                # Creates a dynamic filter like: .filter(employee__institution=user.institution)
                return queryset.filter(**{institution_field: user.institution})
            return queryset.none() # Fails secure if they have no institution

        # 3. REGULAR EMPLOYEE: Can only see their own records
        if employee_field:
            # Creates a dynamic filter like: .filter(employee=user)
            return queryset.filter(**{employee_field: user})

        return queryset.none()