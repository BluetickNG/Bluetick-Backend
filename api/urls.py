from django.urls import path

from . import views

urlpatterns = [
    path('login', views.login),
    path('signup', views.signup),
    path('createworkspace', views.createworkspace),
    path('verify', views.token_verify), #verify workspace creation
    # path('reset', views.resetpassword),
    path('forgotpass', views.forgotpassword),
    path('reset_ver', views.reset_verify),
    path('reset_password', views.reset_password),
    path('user', views.getusers),
    path('addmem', views.addmem),
    path('signemail', views.signemail),
    

]