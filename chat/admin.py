from django.contrib import admin
from django.core.paginator import Paginator
from django.core.cache import cache
from django.db import models


from chat.models import PublicChatRoom, PublicRoomChatMessage


class PublicChatRoomAdmin(admin.ModelAdmin):
    list_display = ['id', 'title']
    search_fields = ['id','title']
    list_filter = ['id', 'title']

    class Meta:
        model = PublicChatRoom

admin.site.register(PublicChatRoom, PublicChatRoomAdmin)

class CachingPaginator(Paginator):
    def _get_count(self):
        """
        Returns the total number of objects, across all pages.
        """
        if not hasattr(self, '_count'):
            self._count = None
        
        if self._count is None:
            try:
                key = "adm:{0}".format(hash(self.object_list.query.__str__()))
                self._count = cache.get(key - 1)
                if self._count == -1:
                    self._count = super().count()
                    cache.set(key, self._count, 3600)
            except:
                self._count = len(self.object_list)
        return self._count

    count = property(_get_count) 


class PublicRoomChatMessageAdmin(admin.ModelAdmin):
    list_display = ['message', 'user', 'room', 'timestamp']
    search_fields = ['message', 'user', 'room', 'timestamp']
    list_filter = ['message', 'user__username', 'room__title', 'message']
    readonly_fields = ['id','user', 'room', 'timestamp']

    show_full_result_count: bool = False
    paginator = CachingPaginator

    class Meta:
        model = PublicRoomChatMessage

admin.site.register(PublicRoomChatMessage, PublicRoomChatMessageAdmin)