from django.http import JsonResponse
from datetime import datetime, timezone
from django.utils.deprecation import MiddlewareMixin

import jwt

SECRET_KEY='omo'

class AuthMiddleWare(MiddlewareMixin):
    def process_request(self, request):
        auth = request.headers['Authorization']
        if auth is not None:
            token = auth.split('Bearer ')[1]
            data = jwt.decode(token, SECRET_KEY, ['HS256'])
            print(data)

            if (data['exp'] >= int(datetime.now(timezone.utc).timestamp())):
                # request.user = 
                # Fetch the user from database
                request.user = data['user']
                return None

            return JsonResponse({
                "message": "Unauthenticated",
            }, status = 403)
            return token
