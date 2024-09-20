from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APIRequestFactory


from user.permission import IsAdminOrEmployer, IsAdminUser, _is_in_group, _has_group_permission, IsLoggedInUserOrAdmin


class UserModelTestCase(TestCase):
    def setUp(self):
        """
        Set up test environment for User model tests.

        This method is called before every test case. It creates a `Group` instance
        and a `User` instance to be used across the test cases.

        Args:
            None

        Returns:
            None
        """
        # Create a Group instance to use for the ForeignKey
        self.group = Group.objects.create(name='Test Group')

        # Create a User instance
        self.user = get_user_model().objects.create_user(
            username='testuser',
            first_name='John',
            last_name='Doe',
            email='johndoe@example.com',
            password='password123',
            groups=self.group
        )

    def test_user_creation(self):
        """
        Test if the User instance is created correctly.

        This test verifies that the `User` instance is created with the expected values
        for the following fields: `username`, `first_name`, `last_name`, `email`,
        and the `groups` foreign key.

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: If any field value does not match the expected value.
        """
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')
        self.assertEqual(self.user.email, 'johndoe@example.com')
        self.assertEqual(self.user.groups, self.group)

    def test_get_full_name(self):
        """
        Test the `get_full_name` method of the User model.

        This test ensures that the `get_full_name` method returns the user's full name,
        which is a combination of the `first_name` and `last_name` separated by a space.

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: If the returned full name does not match the expected format.
        """
        self.assertEqual(self.user.get_full_name(), 'John Doe')

    def test_get_short_name(self):
        """
        Test the `get_short_name` method of the User model.

        This test verifies that the `get_short_name` method returns the `first_name`
        of the user.

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: If the returned short name does not match the expected value.
        """
        self.assertEqual(self.user.get_short_name(), 'John')

    def test_str_method(self):
        """
        Test the `__str__` method of the User model.

        This test ensures that the `__str__` method of the User model correctly returns
        the `username`.

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: If the returned string does not match the expected username.
        """
        self.assertEqual(str(self.user), 'testuser')

    def test_email_unique_constraint(self):
        """
        Test the uniqueness constraint on the email field.

        This test verifies that the `email` field in the User model is unique. It attempts
        to create another user with the same email, and checks if an exception is raised.

        Args:
            None

        Returns:
            None

        Raises:
            Exception: If a user is created with a duplicate email.
        """
        with self.assertRaises(Exception):
            # Attempt to create another user with the same email
            get_user_model().objects.create_user(
                username='testuser2',
                first_name='Jane',
                last_name='Doe',
                email='johndoe@example.com',  # Same email as self.user
                password='password123',
                groups=self.group
            )


class GroupPermissionTestCase(TestCase):

    def setUp(self):
        """
        Set up test environment, creating test groups and users with unique emails.
        """
        # Create test groups
        self.admin_group = Group.objects.create(name='admin')
        self.employer_group = Group.objects.create(name='employer')
        self.client_group = Group.objects.create(name='client')

        # Create test users with unique emails and assign them to respective groups
        self.admin_user = get_user_model().objects.create_user(
            username='admin', password='adminpass', email='admin@example.com', groups=self.admin_group
        )
        self.employer_user = get_user_model().objects.create_user(
            username='employer', password='employerpass', email='employer@example.com', groups=self.employer_group
        )
        self.client_user = get_user_model().objects.create_user(
            username='client', password='clientpass', email='client@example.com', groups=self.client_group
        )

        # Create APIRequestFactory for simulating requests
        self.factory = APIRequestFactory()

    def test_is_in_group(self):
        """
        Test the _is_in_group function.
        """
        # Test admin user is in 'admin' group
        self.assertTrue(_is_in_group(self.admin_user, 'admin'))

        # Test employer user is in 'employer' group
        self.assertTrue(_is_in_group(self.employer_user, 'employer'))

        # Test client user is in 'client' group
        self.assertTrue(_is_in_group(self.client_user, 'client'))

        # Test a user is not in a non-existing group
        self.assertFalse(_is_in_group(self.client_user, 'non_existent_group'))

    def test_has_group_permission(self):
        """
        Test the _has_group_permission function.
        """
        # Test admin has 'admin' permission
        self.assertTrue(_has_group_permission(self.admin_user, ['admin']))

        # Test employer has 'employer' permission
        self.assertTrue(_has_group_permission(self.employer_user, ['employer']))

        # Test user does not have permission for an unrelated group
        self.assertFalse(_has_group_permission(self.client_user, ['admin']))

    def test_is_logged_in_user_or_admin(self):
        """
        Test the IsLoggedInUserOrAdmin permission.
        """
        permission = IsLoggedInUserOrAdmin()

        # Create a request for the admin user
        request = self.factory.get('/')
        request.user = self.admin_user  # Manually assign the user to the request

        # Admin should have object permission for any user
        self.assertTrue(permission.has_object_permission(request, None, self.admin_user))

        # Admin should have object permission for other users as well
        self.assertTrue(permission.has_object_permission(request, None, self.client_user))

        # Test that a non-admin user only has permission for themselves
        request.user = self.client_user
        self.assertTrue(permission.has_object_permission(request, None, self.client_user))
        self.assertFalse(permission.has_object_permission(request, None, self.admin_user))

    def test_is_admin_user_permission(self):
        """
        Test the IsAdminUser permission.
        """
        permission = IsAdminUser()

        # Create a request for the admin user
        request = self.factory.get('/')
        request.user = self.admin_user

        # Admin should have permission
        self.assertTrue(permission.has_permission(request, None))

        # Employer should not have admin permission
        request.user = self.employer_user
        self.assertFalse(permission.has_permission(request, None))

