from django.contrib.auth.models import Group
from rest_framework import permissions


def _is_in_group(user, group_name):
    """
    Takes a user and a group name, and returns `True` if the user is in that group.
    """
    try:
        return Group.objects.get(name=group_name).user_set.filter(id=user.id).exists()
    except Group.DoesNotExist:
        return None

def _has_group_permission(user, required_groups):
    return any([_is_in_group(user, group_name) for group_name in required_groups])


class IsLoggedInUserOrAdmin(permissions.BasePermission):
    # group_name for super admin
    required_groups = ['admin']

    def has_object_permission(self, request, view, obj):
        has_group_permission = _has_group_permission(request.user, self.required_groups)
        if self.required_groups is None:
            return False
        return obj == request.user or has_group_permission


class IsAdminUser(permissions.BasePermission):
    # group_name for super admin
    required_groups = ['admin']

    def has_permission(self, request, view):
        has_group_permission = _has_group_permission(request.user, self.required_groups)
        return request.user and has_group_permission

    def has_object_permission(self, request, view, obj):
        has_group_permission = _has_group_permission(request.user, self.required_groups)
        return request.user and has_group_permission


class IsAdminOrEmployer(permissions.BasePermission):
    required_groups = ['admin', 'employer']

    def has_permission(self, request, view):
        """
        Allow employers to create only clients, and allow full control for admins.
        """
        if request.method == 'POST':
            # Employers are only allowed to create users with the role 'client'
            if _is_in_group(request.user, 'employer'):
                return request.data.get('role') == 'client'
        # Allow admins full access
        return _has_group_permission(request.user, self.required_groups)

    def has_object_permission(self, request, view, obj):
        """
        Object-level permission to allow admins full control and employers to create only clients.
        """
        if request.method == 'POST' and _is_in_group(request.user, 'employer'):
            return request.data.get('role') == 'client'
        return _has_group_permission(request.user, self.required_groups)

    def has_permission(self, request, view):
        has_group_permission = _has_group_permission(request.user, self.required_groups)
        return request.user and has_group_permission