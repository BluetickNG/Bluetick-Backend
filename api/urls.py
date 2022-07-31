from django.urls import path

from . import views

urlpatterns = [
    path('', views.index),
    path('login', views.login),
    path('signup', views.signup),
    path('createworkspace', views.createworkspace),
    path('generate', views.generateLink),
    path('token', views.token_generation),
    path('verify', views.token_verify),
    path('reset', views.resetpassword),
    path('reset_ver', views.reset_verify),
    path('user', views.getusers),

]