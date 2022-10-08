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
    path('getdetails', views.getdetails),
    path('getstaffs', views.getstaffs),
    path('workspacedetails', views.workspacedetails),
    path('getallworkspace', views.getallworkspace),
    path('deleter', views.deleter),
    # URL form : "/api/messages/1/2"
    path('api/messages/<int:sender>/<int:receiver>', views.message_list, name='message-detail'),  # For GET request.
    # URL form : "/api/messages/"
    path('api/messages/', views.message_list, name='message-list'),   # For POST
    # URL form "/api/users/1"
    path('api/users/<int:pk>', views.user_list, name='user-detail'),      # GET request for user with id
    path('api/users/', views.user_list, name='user-list'),    # POST for new user and GET for all users list

]