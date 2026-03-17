from rest_framework import generics, status
from rest_framework.response import Response
from .models import Leave
from .serializers import LeaveSerializer, RegistrationSerializer, UpdatePasswordSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model

Employee = get_user_model()
class LeaveListCreateView(generics.ListCreateAPIView):
    """
    View to list all leave requests for the authenticated user and to create new leave requests.

    Args:
        generics (ListCreateAPIView): Provides GET and POST handlers for listing and creating leave requests.

    Returns:
        A list of leave requests for the authenticated user on GET request, and the created leave request on POST request.
    """
    serializer_class = LeaveSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return the leaves for the currently authenticated user."""
        user = self.request.user

        # HR and Manager can see all leave requests
        if user.employee_role in ['HR', 'MANAGER']:
            return Leave.objects.all()  
        
        return Leave.objects.filter(employee=self.request.user)
    
    def perform_create(self, serializer):
        """Associate the new leave request with the currently authenticated user."""
        serializer.save(employee=self.request.user)

class LeaveDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    View to retrieve, update, or delete a specific leave request.

    Args:
        generics (RetrieveUpdateDestroyAPIView): Provides GET, PUT, PATCH, and DELETE handlers for a specific leave request.
    
    Returns:
        The leave request details on GET request, the updated leave request on PUT/PATCH request,
        and a success message on DELETE request.
    """
    serializer_class = LeaveSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return the leaves for the currently authenticated user."""
        user = self.request.user
        if user.employee_role in ['HR', 'MANAGER']:
            return Leave.objects.all()
        
        return Leave.objects.filter(employee=self.request.user)

class RegistrationView(generics.CreateAPIView):
    """
    View to handle user registration.

    Args:
        generics (CreateAPIView): Provides a POST handler for creating new user accounts.

    Returns:
        The created user account details on successful registration.
    """
    serializer_class = RegistrationSerializer
    permission_classes = [AllowAny]
    queryset = Employee.objects.all()

class UpdatePasswordView(generics.UpdateAPIView):
    """
    View to handle password updates for authenticated users.

    Args:
        generics (UpdateAPIView): Provides a PUT handler for updating the user's password.

    Returns:
        A success message on successful password update, or an error message on failure.
    """
    serializer_class = UpdatePasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """Return the currently authenticated user."""
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        """Handle the password update process, including validation of the old password and setting the new password."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = self.get_object()
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        if not user.check_password(old_password):
            return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)
    