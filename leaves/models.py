from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from datetime import date
from django.conf import settings

class Leave(models.Model):

    LEAVE_TYPE_CHOICES = [
        ('SICK', 'Sick Leave'),
        ('ANN', 'Annual Leave'),
        ('FAMILY', 'Family Responsibility Leave'),
        ('STUDY', 'Study Leave'),
        ('SPECIAL', 'Special Leave'),
    ]
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('CANCELLED', 'Cancelled'),
    ]
    """Model representing a leave request in the leave management system.
    Each leave request has a unique ID, name, type, start and end dates, reason for the leave, and an optional supporting document."""
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPE_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()
    supporting_document = models.FileField(upload_to='leave_documents/', blank=True, null=True)
    status = models.CharField(max_length=20, default='PENDING', choices=STATUS_CHOICES)

    employee = models.ForeignKey(settings.AUTH_USER_MODEL, 
                                 on_delete=models.CASCADE, 
                                 related_name='leaves')

    def clean(self):
        
        """Custom validation to ensure that the end date is not before the start date and that the start date is not in the past."""
        if self.start_date and self.end_date:
            length_of_leave = (self.end_date - self.start_date).days + 1

            if self.end_date < self.start_date:
                raise ValidationError("End date cannot be before start date.")
            if self.start_date < date.today():
                raise ValidationError("Start date cannot be in the past.")
            if length_of_leave <= 0:
                raise ValidationError("Leave duration must be at least one day.")
    
    @property
    def duration(self):
        """Calculate the duration of the leave in days."""
        return (self.end_date - self.start_date).days + 1
    
    def __str__(self):
        return f"{self.leave_name} ({self.leave_type}) from {self.start_date} to {self.end_date}"

class Employee(AbstractUser):
    """Model representing an employee in the leave management system.
    Each employee is associated with a Django User for authentication and has additional fields for department, position, email, and phone number.
    
    Fields:
        employee_department: CharField to store the department of the employee.
        employee_position: CharField to store the position of the employee.
        phone_number: CharField to store the phone number of the employee.
        """
    email = models.EmailField(unique=True)
    EMPLOYEE_ROLE_CHOICES = [
        ('STAFF', 'Staff'),
        ('MANAGER', 'Manager'),
        ('HR', 'Human Resources'),
    ]
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'employee_department', 'employee_position']

    employee_department = models.CharField(max_length=100)
    employee_position = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    employee_role = models.CharField(max_length=20, choices=EMPLOYEE_ROLE_CHOICES, default='STAFF')

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.employee_department} - {self.employee_position})"
