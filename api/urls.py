from django.urls import path

from . import views

urlpatterns = [
    path('', views.index),
    path('login', views.login),
    path('signup', views.signup),
    path('createworkspace', views.createworkspace),
    path('generate', views.generateLink),
]