# from django.db import models
# from django.conf import settings



# class PublicChatRoom(models.Model):
#     title = models.CharField(max_length=255, unique=True, blank=False)

#     users = models.ManyToManyField(settings.AUTH_USER_MODEL,blank=True, help_text='Users in this chat room')

#     def __str__(self):
#         return self.title

#     def connect(self, user):
#         """
#         return true if user is added to the user list
#         """
#         is_user_added = False
#         if user not in self.users.all():
#             self.users.add(user)
#             self.save()
#             is_user_added = True
#         elif user in self.users.all():
#             is_user_added = False

#         return is_user_added

#     def disconnect(self, user):
#         """
#         return true if user is removed from the user list
#         """
#         is_user_removed = False
#         if user in self.users.all():
#             self.users.remove(user)
#             self.save()
#             is_user_removed = True
#         return is_user_removed

# @property
# def group_name(self):
#     """
#     Returns the group name that sockets should subscribe to and get sent messages as they are generated"""
#     return f"PublicChatRoom-{self.id}"


# class PublicRoomChatMessageManager(models.Manager):
#     def by_room(self, room):
#         qs = PublicRoomChatMessage.objects.filter(room=room).order_by('-timestamp')
#         return qs

# class PublicRoomChatMessage(models.Model):
#     """
#     chat message crated by a user inside a public chat room (foreign key)
#     """
#     message = models.TextField(blank=False, unique= False)
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
#     room = models.ForeignKey(PublicChatRoom, on_delete=models.CASCADE)
#     timestamp = models.DateTimeField(auto_now_add=True)


#     objects = PublicRoomChatMessageManager()

#     def __str__(self):
#         return self.message