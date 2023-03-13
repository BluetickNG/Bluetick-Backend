from django.contrib import admin

# Register your models here.
from .models import UserManager, User, Log, Domain, invitation, Worklog, Message

admin.site.register(Domain)
admin.site.register(Worklog)
# admin.site.register(UserManager)
admin.site.register(User)
admin.site.register(Log)
admin.site.register(invitation)
admin.site.register(Message)
