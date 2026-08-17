from django.core.management.base import BaseCommand
from leaves.models import Permission, Role

DEFAULT_PERMISSIONS = [
    ("employee.view", "View employees", "Employee"),
    ("employee.create", "Create employees", "Employee"),
    ("employee.edit", "Edit employees", "Employee"),
    ("employee.delete", "Delete/deactivate employees", "Employee"),
    ("leave.create", "Submit a leave request", "Leave"),
    ("leave.cancel_own", "Cancel own leave request", "Leave"),
    ("leave.cancel_any", "Cancel any leave request", "Leave"),
    ("leave.approve", "Approve leave requests", "Leave"),
    ("leave.reject", "Reject leave requests", "Leave"),
    ("leave.download_document_any", "Download any employee's supporting document", "Leave"),
    ("leave_type.manage", "Create/edit/deactivate leave types", "LeaveType"),
    ("institution.manage", "Create/edit institutions", "Institution"),
    ("role.manage", "Create/edit roles and permission assignments", "Role"),
    ("report.view", "View reports and department breakdowns", "Reports"),
]

# name -> (data_scope, grants_django_admin, [permission codes])
DEFAULT_ROLES = {
    "STAFF":    ("OWN",         False, ["leave.create", "leave.cancel_own"]),
    "MANAGER":  ("INSTITUTION", False, ["employee.view", "employee.create",
                                         "leave.create", "leave.cancel_own", "report.view"]),
    "HR":       ("INSTITUTION", True,  ["employee.view", "employee.create",
                                         "leave.create", "leave.cancel_own", "report.view"]),
    "DIRECTOR": ("GLOBAL",      True,  [c for c, _, _ in DEFAULT_PERMISSIONS]),
    "ADMIN":    ("GLOBAL",      True,  [c for c, _, _ in DEFAULT_PERMISSIONS]),
}


class Command(BaseCommand):
    help = "Seeds default Permission and system Role instances."

    def handle(self, *args, **options):
        self.stdout.write("Seeding permissions...")
        perms = {}
        for code, label, category in DEFAULT_PERMISSIONS:
            perms[code], created = Permission.objects.get_or_create(
                code=code, defaults={"label": label, "category": category}
            )
            if created:
                self.stdout.write(f"  Created permission: {code}")

        self.stdout.write("Seeding roles...")
        for name, (scope, admin_flag, codes) in DEFAULT_ROLES.items():
            role, created = Role.objects.get_or_create(
                name=name, institution=None,
                defaults={"data_scope": scope, "is_system": True, "grants_django_admin": admin_flag},
            )
            role.permissions.set([perms[c] for c in codes])
            if created:
                self.stdout.write(f"  Created role: {name}")

        self.stdout.write(self.style.SUCCESS("Successfully seeded RBAC roles and permissions."))
