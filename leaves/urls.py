from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    # Auth views
    LoginView,
    LogoutView,
    SetPassword,
    PasswordResetRequestView,
    MeView,
    # Resource ViewSets
    InstitutionViewSet,
    EmployeeViewSet,
    LeaveTypeViewSet,
    LeaveViewSet,
    NotificationViewSet,
    PostLoginPasswordView,
    RoleViewSet,
    PermissionViewSet,
)
from rest_framework_simplejwt.views import TokenRefreshView

# Initialize router for ViewSets
router = DefaultRouter()
router.register(r'institutions', InstitutionViewSet, basename='institution')
router.register(r'employees', EmployeeViewSet, basename='employee')
router.register(r'leave-types', LeaveTypeViewSet, basename='leave-type')
router.register(r'leaves', LeaveViewSet, basename='leave')
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'roles', RoleViewSet, basename='role')
router.register(r'permissions', PermissionViewSet, basename='permission')

urlpatterns = [
    # Include all ViewSet routes
    path('', include(router.urls)),
    
    # =============================
    # AUTH ENDPOINTS
    # =============================

    #=========== AUTH ===================
    path('auth/login/', LoginView.as_view(), name='auth-login'),
    path('auth/logout/', LogoutView.as_view(), name='auth-logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/me/', MeView.as_view(), name='auth-me'),

    #======= PASSWORD FLOWS ==============

    path('auth/password-reset/', PasswordResetRequestView.as_view(), name='auth-password-reset-request'),
    path('auth/set-password/', SetPassword.as_view(), name='auth-set-password'),
    path('auth/set-password-post-login/', PostLoginPasswordView.as_view(), name='auth-set-password-post-login'),
   
]
