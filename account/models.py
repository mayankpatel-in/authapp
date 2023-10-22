from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        # A defult value set while creating the superuser
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
    
    def create_sol_provider(self, email, password=None, **extra_fields):
        # Create a user with solution provider role
        extra_fields.setdefault('role', self.model.SOL_PROVIDER)
        return self.create_user(email, password, **extra_fields)

    def create_sol_seeker(self, email, password=None, **extra_fields):
        # Create a user with solution seeker role
        extra_fields.setdefault('role', self.model.SOL_SEEKER)
        return self.create_user(email, password, **extra_fields)

    def create_admin(self, email, password=None, **extra_fields):
        # Create a user with admin role
        extra_fields.setdefault('role', self.model.ADMIN)
        return self.create_user(email, password, **extra_fields)
    
# Create custom user for email based login and assign role.
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Define choices for user role
    ADMIN = 'admin'
    SOL_PROVIDER = 'sol_provider'
    SOL_SEEKER = 'sol_seeker'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (SOL_PROVIDER, 'Solution Provider'),
        (SOL_SEEKER, 'Solution Seeker'),
    ]

    # Assign a role to the user for controll access 
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=SOL_SEEKER,) 

    objects = UserManager()

    # Set email field as a username, So user can login via email
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def is_admin(self):
        return self.role == self.ADMIN

    def is_sol_provider(self):
        return self.role == self.SOL_PROVIDER

    def is_sol_seeker(self):
        return self.role == self.SOL_SEEKER

    def __str__(self):
        return self.email

    
# User profile model for store user personal details 
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=50, null=True)
    last_name = models.CharField(max_length=50, null=True)
    phone_number = models.CharField(max_length=10, unique=True)
    
    def __str__(self):
        return self.user.email
    

# Store random otp in this field (For validate the otp)
class OTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)  
    timestamp = models.DateTimeField(auto_now=True)  # Checking OTP expire time here
