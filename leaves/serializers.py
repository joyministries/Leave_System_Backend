from rest_framework import serializers
from .models import Leave, Employee
from datetime import date       

class LeaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Leave
        fields = '__all__'
        # Ensure employee is set from the request context, not the client
        read_only_fields = ['employee']  

    list_display = ('leave_type','start_date', 'end_date', 'reason', 'status')
    search_fields = ('leave_type','reason', 'status')
    list_filter = ('start_date', 'end_date', 'leave_type', 'status')


    def validate(self, data):
        """Custom validation to ensure that the end date is not before the start date and that the start date is not in the past."""
        if data['end_date'] < data['start_date']:
            raise serializers.ValidationError("End date cannot be before start date.")
        if data['start_date'] < date.today():
            raise serializers.ValidationError("Start date cannot be in the past.")
        
    
        leave_type = data.get('leave_type')
        document = data.get('supporting_document')

        leaves_requiring_document = ['SICK','STUDY']

        if leave_type in leaves_requiring_document and not document:
            raise serializers.ValidationError(f"{leave_type} leave requires a supporting document.")    
        return data
    
class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, 
                                     required=True, 
                                     style={'input_type': 'password'},
                                     min_length=8)
    class Meta:
        model = Employee
        fields = ['first_name', 'last_name', 'email', 'employee_department', 'employee_position', 'phone_number', 'employee_role', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """Create a new employee instance with the provided validated data."""
        password = validated_data.pop('password')
        employee = Employee(**validated_data)
        employee.set_password(password)  # Hash the password before saving
        employee.save()
        return employee

class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'}, min_length=8)