from django.urls import path

from . import views

urlpatterns = [
    path('', views.index),
    path('login', views.login),
    path('signup', views.signup),
    path('email-verify', views.VerifyEmail.as_view(), name='email-verify'),
]