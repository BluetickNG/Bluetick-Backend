from django.db import models

# Create your models here.

class User(models.Model):
    first_name = models.CharField(max_length=25)
    last_name = models.CharField(max_length=25)
    middle_name = models.CharField(max_length=25)

    email = models.CharField(max_length=50, unique=True)
    password = models.BinaryField()
    username = models.CharField(max_length=20, unique=True)

    is_admin = models.BooleanField(default=False)
    is_manager = models.BooleanField(default=False)
    is_super = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)

    domain = models.TextField()

    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)


class Log(models.Model):
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)
    # login, logout, message
    type = models.CharField(max_length=50)
    # {
    #   "lat": xxx,
    #   "long": xxx,
    # }
    location = models.TextField()
    user = User
    data = models.TextField()
    

class Notifications(models.Model):
    sent_at = models.DateTimeField(auto_now = True)
    message = models.TextField()
    user = User
    employee_id = User.email

