from django.db import models

# Create your models here.

class User(models.Model):
    full_name = models.CharField(max_length=250, null=True)
    role = models.CharField(max_length=50)
    email = models.CharField(max_length=225, unique=True)
    password = models.BinaryField()

    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)


    domain = models.TextField()
    
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)
    # invitation_link = models.CharField(max_length=100, null=True)
    # last_name = models.CharField(max_length=25)
    # middle_name = models.CharField(max_length=25)
    # department = models.CharField(max_length=25)

    # email = models.ForeignKey('invitation', on_delete=models.CASCADE)
    # red = models.foreignKey('Red', on_delete=models.CASCADE)
    # username = models.CharField(max_length=20, unique=True)
    

    # the invitation link

    # is_manager = models.BooleanField(default=False)
    # is_super = models.BooleanField(default=False)



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
    

class Domain(models.Model):
    company_name = models.CharField(max_length=100, unique=True)
    company_email = models.EmailField(max_length=100, unique=True)
    company_phone = models.CharField(max_length=100)
    password = models.BinaryField()

    created_at = models.DateTimeField(auto_now=True)

    is_admin = models.BooleanField(default=True)


# model for invitatoin link part
class invitation(models.Model):
    email = models.EmailField(max_length=50)
    invitation_link = models.CharField(max_length=250, unique=True)




class token(models.Model):
    otp = models.CharField(max_length=250, unique=True)
    email = models.EmailField(max_length=50)
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'otp'
        ordering = ['-created_at']

