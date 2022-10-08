from email.policy import default
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
# Create your models here.

# class User(models.Model):
#     full_name = models.CharField(max_length=250, null=True)
#     role = models.CharField(max_length=50, default="Null")
#     email = models.CharField(max_length=225, unique=True)
#     password = models.BinaryField()
#     profile_img = models.ImageField(upload_to='profile_img', default = 'blank-profile-picture.png')
#     # profile_img = models.ImageField(upload_to='profile_img', default = 'https://res.cloudinary.com/dg4zlcau8/image/upload/v1661916483/blank-profile-picture_v6ojkd.png')

#     is_admin = models.BooleanField(default=False)
#     is_staff = models.BooleanField(default=True)

#     pas_reset = models.BooleanField(default=False)

#     domain = models.TextField()
    
#     created_at = models.DateTimeField(auto_now=True) #format='%Y-%m-%d %H:%M:%S')
#     updated_at = models.DateTimeField(auto_now=True)
    



    # class Meta:
    #     db_table = 'api_user'
    #     # ordering = ['-created_at']





class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)






class User(AbstractUser):
    # username = None
    last_login = None
    first_name = None
    last_name = None

    username = None
    email = models.EmailField(('email address'), unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    full_name = models.CharField(max_length=250, null=True)
    role = models.CharField(max_length=50, default="Null")
    profile_img = models.ImageField(upload_to='profile_img', default = 'blank-profile-picture.png')
    domain = models.CharField(max_length=300)
    pas_reset = models.BooleanField(default=False)

    objects = UserManager()

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = '1. Users'

    def _str_(self):
        return self.full_name

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
    # user = User
    data = models.TextField()
    

class Domain(models.Model):
    company_name = models.CharField(max_length=100, unique=True)
    company_email = models.EmailField(max_length=100, unique=True)
    company_phone = models.CharField(max_length=100)
    password = models.BinaryField()
    verified = models.BooleanField(default=False)
    pas_reset = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now=True)

    is_admin = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    Workspace_profile_img =  models.ImageField(upload_to='workspcae_img', default = 'blank-profile-picture.png')
    # is_staff = models.BooleanField(default=True)



# model for invitatoin link part
class invitation(models.Model):
    email = models.EmailField(max_length=100)
    invitation_link = models.CharField(max_length=250, unique=True)
    workspacename = models.CharField(max_length=250 )
    created_at = models.DateTimeField(auto_now=True)

class Worklog(models.Model):
    email = models.EmailField(max_length=100)
    date = models.DateField()
    clockintime = models.TimeField(default="00:00:00.00")
    clockouttime = models.TimeField(default="00:00:00.00")
    workhour = models.TimeField(default="00:00:00.00")
    workspace = models.CharField(max_length=100)    

class Message(models.Model):
    User = User()
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver')
    message = models.CharField(max_length=1200)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return self.message

    class Meta:
        ordering = ('timestamp',)
