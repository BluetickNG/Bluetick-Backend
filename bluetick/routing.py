from email.mime import application
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator

from chat import routing

from django.urls import path

application = ProtocolTypeRouter({
    # 'websocket': AllowedHostsOriginValidator(
    #     AuthMiddlewareStack(
    #         # URLRouter()
    #     )
    # )
    'websocket': AllowedHostsOriginValidator(
        routing.websocket_urlpatterns
    )
})

