from django.shortcuts import redirect, render
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet, ModelViewSet
from rest_framework.authtoken.models import Token
from user.permission import IsAdminUser, IsLoggedInUserOrAdmin, IsAdminOrAnonymousUser
from user.models import User
from user.serializer import UserSerializer
from functools import wraps
from django.shortcuts import redirect
from rest_framework.authtoken.models import Token


def token_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        token_key = request.session.get('auth_token')
        if token_key:
            try:
                token = Token.objects.get(key=token_key)
                request.user = token.user
                return view_func(request, *args, **kwargs)
            except Token.DoesNotExist:
                pass

        return redirect("http://127.0.0.1:8000/api-auth/login/?next=/login/")

    return _wrapped_view


@token_required
def dashboard(request):
    def get_permissions(self):
        permission_classes = []
        if self.action == 'create':
            permission_classes = [IsAdminUser]
        elif self.action == 'list':
            permission_classes = [IsAdminOrAnonymousUser]
        elif self.action == 'retrieve' or self.action == 'update' or self.action == 'partial_update':
            permission_classes = [IsLoggedInUserOrAdmin]
        elif self.action == 'destroy':
            permission_classes = [IsLoggedInUserOrAdmin]
        return [permission() for permission in permission_classes]
    return render(request, 'dashboard.html')


@token_required
def clients(request):
    return render(request, 'edit_client.html')


@token_required
def employers(request):
    return render(request, 'edit_employer.html')


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        permission_classes = []
        if self.action == 'create':
            permission_classes = [IsAdminUser]
        elif self.action == 'list':
            permission_classes = [IsAuthenticated]  # Modify as needed
        elif self.action in ['retrieve', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_authenticators(self):
        """Override to use token from session if available."""
        authenticators = super().get_authenticators()

        # Check if the token is stored in the session
        token = self.request.session.get('auth_token')
        if token:
            # If the token is in the session, set it as the `Authorization` header
            self.request.META['HTTP_AUTHORIZATION'] = f'Token {token}'

        return authenticators


class LoginView(ViewSet):
    serializer_class = AuthTokenSerializer
    def create(self, request):
        # Manually initialize the serializer
        serializer = self.serializer_class(data=request.data)

        # Validate the data
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            request.session['auth_token'] = token.key
            return redirect("http://127.0.0.1:8000/dashboard/")
        else:
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    def post(self, request, *args, **kwargs):
        # Remove token from the session
        if 'auth_token' in request.session:
            del request.session['auth_token']
        # Redirect to login page
        return redirect('http://127.0.0.1:8000/api-auth/login/?next=/login/')


def login(request):
    return redirect("http://127.0.0.1:8000/login/")
