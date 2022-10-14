from django.contrib import admin

from .models import User, Domain
# Register your models here.
admin.site.register(User)
admin.site.register(Domain)