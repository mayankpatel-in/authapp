from django.contrib import admin
from django.urls import path
from account.views import UserRegistrationAPIView, UserLoginAPIView, UserProfileCreateAPIView, UserProfileUpdateAPIView,ChangePasswordAPIView, PasswordResetConfirmView, ForgotPasswordAPIView, SolutionProviderView, SolutionSeekerView, SendOTPView, VerifyOTPView

urlpatterns = [
    path('admin/', admin.site.urls),

    # New user registration here
    path('register/', UserRegistrationAPIView.as_view(), name='register'),

    # Login using email and password
    path('login/', UserLoginAPIView.as_view(), name='login'),
    
    # OTP based login url path
    path('send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),

    # Create and update user profile
    path('profile/create/', UserProfileCreateAPIView.as_view(), name='create_profile'),
    path('profile/update/', UserProfileUpdateAPIView.as_view(), name='update_profile'),

    # Change and forget password API path
    path('change_password/', ChangePasswordAPIView.as_view(), name='change_password'),
    path('forgot_password/', ForgotPasswordAPIView.as_view(), name='forgot_password'),
    path('password_reset_confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    # Role based access area path is here
    path('api/solution-provider/', SolutionProviderView.as_view(), name='solution_provider_api'),
    path('api/solution-seeker/', SolutionSeekerView.as_view(), name='solution_seeker_api'),
]
