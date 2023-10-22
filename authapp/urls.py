from django.contrib import admin
from django.urls import path
from account.views import UserRegistrationAPIView, UserLoginAPIView, UserProfileCreateAPIView, UserProfileUpdateAPIView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', UserRegistrationAPIView.as_view(), name='register'),
    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('profile/create/', UserProfileCreateAPIView.as_view(), name='create_profile'),
    path('profile/update/', UserProfileUpdateAPIView.as_view(), name='update_profile'),
]
