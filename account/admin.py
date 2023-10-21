from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext as _

from .models import User, UserProfile

class UserAdmin(BaseUserAdmin):
    ordering = ['id']
    list_display = ['email', 'is_staff', 'role']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ()}),  # You can add more personal info fields here
        (
            _('Permissions'),
            {
                'fields': (
                    'is_active',
                    'is_staff',
                    'is_superuser',
                    'role',
                ),
            },
        ),
        (_('Important dates'), {'fields': ('last_login',)}),
    )
    
    # If you're allowing admin creation of users, you'll need to define
    # the fields that will be used on the creation form.
    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': ('email', 'password1', 'password2', 'is_staff', 'is_active', 'role'),
            },
        ),
    )

# Register your models here.
admin.site.register(User, UserAdmin)

# If you have a user profile and want to include it in the admin, you can register it like this.
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number']
    search_fields = ['user__email', 'phone_number']

    # You can add more configuration for the UserProfile if needed.
