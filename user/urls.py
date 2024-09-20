from django.shortcuts import redirect
from rest_framework.routers import DefaultRouter
from django.urls import path, include

from user import views

router = DefaultRouter()
router.register('users', views.UserViewSet, 'user-list')
router.register('login', views.LoginView, 'login')

urlpatterns = [
    path('', lambda request: redirect('login/')),
    path('', include(router.urls)),
    path('users/', lambda request: redirect('users/')),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('clients/', views.clients, name='clients'),
    path('employers/', views.employers, name='employers'),
]
