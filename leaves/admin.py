from django.contrib import admin
from .models import Leave, Employee, Notification, Permission, Role, InstitutionSettings


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("code", "label", "category")
    list_filter = ("category",)
    search_fields = ("code", "label", "category")


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "institution", "data_scope", "is_system", "grants_django_admin")
    list_filter = ("data_scope", "is_system", "grants_django_admin", "institution")
    search_fields = ("name",)
    filter_horizontal = ("permissions",)


@admin.register(InstitutionSettings)
class InstitutionSettingsAdmin(admin.ModelAdmin):
    list_display = ("institution", "default_role", "allow_self_cancel", "require_second_approval_over_days", "max_consecutive_leave_days")


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("recipient", "notification_type", "message", "is_read", "created_at")
    list_filter = ("notification_type", "is_read", "created_at")
    search_fields = ("recipient__email", "message")


@admin.action(description="Approve selected leave requests")
def approve_leaves(modeladmin, request, queryset):
    updated_count = queryset.update(status="APPROVED")
    modeladmin.message_user(request, f"{updated_count} leave requests approved.")

@admin.action(description="Reject selected leave requests")
def reject_leaves(modeladmin, request, queryset):
    updated_count = queryset.update(status="REJECTED")
    modeladmin.message_user(request, f"{updated_count} leave requests rejected.")


@admin.register(Leave)
class LeaveAdmin(admin.ModelAdmin):
    list_display = ('leave_type', 'start_date', 'end_date', 'reason', 'status', 'employee')
    search_fields = ('leave_type__name', 'reason')
    list_filter = ('start_date', 'end_date', 'leave_type')
    actions = [approve_leaves, reject_leaves]


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ("email", "department", "position", "role")
    actions = ["make_hr", "make_staff", "make_manager"]

    @admin.action(description="Update role to HR")
    def make_hr(self, request, queryset):
        try:
            role = Role.objects.get(name="HR", institution=None)
            queryset.update(role=role)
            self.message_user(request, f"Successfully updated {queryset.count()} employee(s) to HR.")
        except Role.DoesNotExist:
            self.message_user(request, "HR system role does not exist. Run seed_rbac command first.", level="error")

    @admin.action(description="Update role to Staff")
    def make_staff(self, request, queryset):
        try:
            role = Role.objects.get(name="STAFF", institution=None)
            updated_count = queryset.update(role=role)
            self.message_user(request, f"Successfully updated {updated_count} employee(s) to Staff.")
        except Role.DoesNotExist:
            self.message_user(request, "STAFF system role does not exist. Run seed_rbac command first.", level="error")

    @admin.action(description="Update role to Manager")
    def make_manager(self, request, queryset):
        try:
            role = Role.objects.get(name="MANAGER", institution=None)
            updated_count = queryset.update(role=role)
            self.message_user(request, f"Successfully updated {updated_count} employee(s) to Manager.")
        except Role.DoesNotExist:
            self.message_user(request, "MANAGER system role does not exist. Run seed_rbac command first.", level="error")
