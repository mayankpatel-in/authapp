from rest_framework import permissions

class IsAdmin(permissions.BasePermission):

    def has_permission(self, request, view):
        # check the user is authenticated and is an admin
        return bool(request.user and request.user.is_authenticated and request.user.is_admin())

class IsSolutionProvider(permissions.BasePermission):

    def has_permission(self, request, view):
        # check the user is authenticated and is a solution provider
        return bool(request.user and request.user.is_authenticated and (request.user.is_sol_provider() or request.user.is_admin()))

class IsSolutionSeeker(permissions.BasePermission):

    def has_permission(self, request, view):
        # check the user is authenticated and is a solution seeker
        return bool(request.user and request.user.is_authenticated and (request.user.is_sol_seeker() or request.user.is_admin()))
