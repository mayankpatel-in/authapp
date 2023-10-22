from django.contrib import admin
from django.urls import path
from account.views import UserRegistrationAPIView, UserLoginAPIView, UserProfileCreateAPIView, UserProfileUpdateAPIView,ChangePasswordAPIView, PasswordResetConfirmView, ForgotPasswordAPIView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', UserRegistrationAPIView.as_view(), name='register'),
    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('profile/create/', UserProfileCreateAPIView.as_view(), name='create_profile'),
    path('profile/update/', UserProfileUpdateAPIView.as_view(), name='update_profile'),
    path('change_password/', ChangePasswordAPIView.as_view(), name='change_password'),
    path('forgot_password/', ForgotPasswordAPIView.as_view(), name='forgot_password'),
    path('password_reset_confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
