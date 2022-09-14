from email.policy import default
from django.db import models

# Create your models here.

class User(models.Model):
    full_name = models.CharField(max_length=250, null=True)
    role = models.CharField(max_length=50, default="Null")
    email = models.CharField(max_length=225, unique=True)
    password = models.BinaryField()
    profile_img = models.ImageField(upload_to='profile_img', default = 'blank-profile-picture.png')
    # profile_img = models.ImageField(upload_to='profile_img', default = 'https://res.cloudinary.com/dg4zlcau8/image/upload/v1661916483/blank-profile-picture_v6ojkd.png')

    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)

    pas_reset = models.BooleanField(default=False)

    domain = models.TextField()
    
    created_at = models.DateTimeField(auto_now=True) #format='%Y-%m-%d %H:%M:%S')
    updated_at = models.DateTimeField(auto_now=True)
    



    class Meta:
        db_table = 'api_user'
        # ordering = ['-created_at']


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
    

# class Domain(models.Model):
#     company_name = models.CharField(max_length=100, unique=True)
#     company_email = models.EmailField(max_length=100, unique=True)
#     company_phone = models.CharField(max_length=100)
#     password = models.BinaryField()
#     verified = models.BooleanField(default=False)
#     pas_reset = models.BooleanField(default=False)

#     created_at = models.DateTimeField(auto_now=True)

#     is_admin = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=True)
#     Workspace_profile_img =  models.ImageField(upload_to='workspcae_img', default = 'blank-profile-picture.png')
#     # is_staff = models.BooleanField(default=True)


# model for invitatoin link part
class invitation(models.Model):
    email = models.EmailField(max_length=100)
    invitation_link = models.CharField(max_length=250, unique=True)
    workspacename = models.CharField(max_length=250 )

class Worklog(models.Model):
    email = models.EmailField(max_length=100)
    date = models.DateField()
    clockintime = models.TimeField(default="00:00:00.00")
    clockouttime = models.TimeField(default="00:00:00.00")
    workhour = models.TimeField(default="00:00:00.00")
    workspace = models.CharField(max_length=100)    


