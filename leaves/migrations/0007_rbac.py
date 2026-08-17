import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


# ---------------------------------------------------------------------------
# Helper used by the data-migration step
# ---------------------------------------------------------------------------
LEGACY_ROLE_MAP = {
    "STAFF":    {"data_scope": "OWN",         "grants_django_admin": False},
    "MANAGER":  {"data_scope": "INSTITUTION", "grants_django_admin": False},
    "HR":       {"data_scope": "INSTITUTION", "grants_django_admin": False},
    "DIRECTOR": {"data_scope": "GLOBAL",      "grants_django_admin": False},
    "ADMIN":    {"data_scope": "GLOBAL",      "grants_django_admin": True},
}


def create_system_roles_and_migrate(apps, schema_editor):
    """
    1. Create one system Role row for every legacy text-role value that exists
       in the Employee table (or all five if none exist yet).
    2. Add a temporary FK column `role_new_id`.
    3. Point every employee's `role_new_id` at the matching Role row.
    """
    Role = apps.get_model("leaves", "Role")
    Employee = apps.get_model("leaves", "Employee")

    # Collect which legacy values are actually in use (or use all five)
    used_values = (
        Employee.objects.values_list("role", flat=True)
        .distinct()
        .exclude(role__isnull=True)
        .exclude(role="")
    )
    codes_to_create = set(used_values) or set(LEGACY_ROLE_MAP.keys())

    # Create a system Role for each code (skip if already exists)
    role_objects = {}
    for code in LEGACY_ROLE_MAP:
        cfg = LEGACY_ROLE_MAP[code]
        obj, _ = Role.objects.get_or_create(
            name=code,
            institution=None,
            defaults={
                "data_scope": cfg["data_scope"],
                "grants_django_admin": cfg["grants_django_admin"],
                "is_system": True,
            },
        )
        role_objects[code] = obj

    # Point each employee at the matching Role
    for code, role_obj in role_objects.items():
        Employee.objects.filter(role=code).update(role_fk_id=role_obj.pk)


def reverse_migrate(apps, schema_editor):
    """Restore text role values from the Role name."""
    Employee = apps.get_model("leaves", "Employee")
    Role = apps.get_model("leaves", "Role")

    for role_obj in Role.objects.filter(is_system=True):
        Employee.objects.filter(role_fk_id=role_obj.pk).update(role=role_obj.name)


class Migration(migrations.Migration):

    dependencies = [
        ("leaves", "0006_notification"),
    ]

    operations = [
        # ------------------------------------------------------------------
        # 1. Create Permission, Role, InstitutionSettings tables
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="Permission",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(help_text="e.g. 'leave.approve'", max_length=100, unique=True)),
                ("label", models.CharField(max_length=255)),
                ("category", models.CharField(blank=True, help_text="e.g. 'Leave', 'Employee'", max_length=50)),
            ],
            options={
                "ordering": ["category", "code"],
            },
        ),
        migrations.CreateModel(
            name="Role",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100)),
                ("data_scope", models.CharField(
                    choices=[
                        ("OWN", "Own records only"),
                        ("INSTITUTION", "Everything in their own institution"),
                        ("GLOBAL", "Everything, across all institutions"),
                    ],
                    default="OWN",
                    max_length=20,
                )),
                ("is_system", models.BooleanField(default=False, help_text="Seeded default role. Cannot be deleted.")),
                ("grants_django_admin", models.BooleanField(default=False)),
                ("institution", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="roles",
                    to="leaves.institution",
                )),
                ("permissions", models.ManyToManyField(blank=True, related_name="roles", to="leaves.permission")),
            ],
            options={
                "ordering": ["institution__name", "name"],
                "unique_together": {("name", "institution")},
            },
        ),
        migrations.CreateModel(
            name="InstitutionSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("allow_self_cancel", models.BooleanField(default=True)),
                ("require_second_approval_over_days", models.PositiveIntegerField(blank=True, null=True)),
                ("max_consecutive_leave_days", models.PositiveIntegerField(blank=True, null=True)),
                ("default_role", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to="leaves.role",
                )),
                ("institution", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="settings",
                    to="leaves.institution",
                )),
            ],
        ),

        # ------------------------------------------------------------------
        # 2. Add a TEMPORARY nullable FK column so we can copy data across
        # ------------------------------------------------------------------
        migrations.AddField(
            model_name="employee",
            name="role_fk",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="employees",
                to="leaves.role",
                db_column="role_fk_id",
            ),
        ),

        # ------------------------------------------------------------------
        # 3. Data migration: seed Role rows + populate role_fk for every employee
        # ------------------------------------------------------------------
        migrations.RunPython(create_system_roles_and_migrate, reverse_migrate),

        # ------------------------------------------------------------------
        # 4. Drop the old text column
        # ------------------------------------------------------------------
        migrations.RemoveField(
            model_name="employee",
            name="role",
        ),

        # ------------------------------------------------------------------
        # 5. Rename role_fk → role  (gives us the final column name)
        # ------------------------------------------------------------------
        migrations.RenameField(
            model_name="employee",
            old_name="role_fk",
            new_name="role",
        ),

        # ------------------------------------------------------------------
        # 6. Add the institution FK to Leave (was also in original 0007)
        # ------------------------------------------------------------------
        migrations.AddField(
            model_name="leave",
            name="institution",
            field=models.ForeignKey(
                blank=True, editable=False,
                help_text="Denormalized from employee.institution at creation time.",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="leaves",
                to="leaves.institution",
            ),
        ),
    ]
