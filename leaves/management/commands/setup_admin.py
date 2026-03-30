from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from leaves.models import Institution, LeaveType
from dotenv import load_dotenv
import os

load_dotenv() 

class Command(BaseCommand):
    help = 'Creates initial admin, default institution, and standard leave types'

    def handle(self, *args, **kwargs):
        Employee = get_user_model()

        self.stdout.write("Starting database initialization...")

        # 1. Create Default Institution
        institution, created = Institution.objects.get_or_create(
            name="Team Impact Christian University",
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'Created Institution: {institution.name}'))

        # 2. Create Initial Leave Types
        # This matches the LEAVE_TYPE_LABELS mapped in your React frontend
        leave_types = [
            {"name": "Annual Leave", "max_days": 21, "allowed_month": None},
            {"name": "Sick Leave", "max_days": 14, "allowed_month": None},
            {"name": "Family Responsibility Leave", "max_days": 5, "allowed_month": None},
            {"name": "Study Leave", "max_days": 10, "allowed_month": None},
            {"name": "Special Leave", "max_days": 5, "allowed_month": 6}, # Restricted to June
        ]

        for lt_data in leave_types:
            obj, created = LeaveType.objects.get_or_create(
                name=lt_data["name"],
                defaults={
                    "max_days": lt_data["max_days"],
                    "allowed_month": lt_data["allowed_month"]
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created Leave Type: {obj.name}'))

        # 3. Create the Initial Superuser
        admin_email = os.getenv("ADMIN_EMAIL")
        admin_password = os.getenv("ADMIN_PASSWORD")

        if not Employee.objects.filter(email=admin_email).exists():
            admin = Employee.objects.create_superuser(
                email=admin_email,
                password=admin_password,
                first_name="System",
                last_name="Administrator",
                role=Employee.Role.ADMIN,
                institution=institution,
                department="System",
                position="Director"
            )
            
            # Explicitly set this to False so you don't get locked out by your own 
            # must_reset_password frontend routing logic on the very first login.
            admin.must_reset_password = False
            admin.save(update_fields=["must_reset_password"])
            
            self.stdout.write(self.style.SUCCESS(f'Successfully created admin account: {admin_email}'))
            self.stdout.write(self.style.WARNING(f'Temporary Password: {admin_password}'))
        else:
            self.stdout.write(self.style.WARNING(f'Admin user ({admin_email}) already exists. Skipping creation.'))

        self.stdout.write(self.style.SUCCESS('Database initialization complete!'))