from rest_framework.permissions import BasePermission, IsAuthenticated



# Define role constants
ROLE_ADMIN = 'admin'
ROLE_CREATOR = 'creator'
ROLE_MODERATOR = 'moderator'


class HasRole1(BasePermission):
    """Permissions for admin, creator, and moderator"""
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and
            request.user.groups.filter(name__in=[ROLE_ADMIN, ROLE_MODERATOR]).exists()
        )


class HasRole(BasePermission):
    """Permissions for admin, creator, and moderator"""
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and
            request.user.groups.filter(name__in=[ROLE_ADMIN, ROLE_CREATOR, ROLE_MODERATOR]).exists()
        )


class IsAdmin(BasePermission):
    """Rights only for admin"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.groups.filter(name='admin').exists() )
    

class IsCreator(BasePermission):
    """Rights only for creator"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.groups.filter(name='create').exists())
    

class IsModerator(BasePermission):
    """Rights only for moderator"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.groups.filter(name='moderator').exists() )
    

class IsLogin(BasePermission):
    """Rights only for Login"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated)


class IsUser(BasePermission):
    """Rights only for user"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.groups.filter(name='user').exists() )