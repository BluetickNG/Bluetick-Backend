from datetime import datetime, timedelta, timezone
from django.http import Http404, HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import render
from django.http.response import JsonResponse, HttpResponse,HttpResponseBadRequest
from django.core.exceptions import ObjectDoesNotExist

import bcrypt
import jwt

from django.views.decorators.csrf import csrf_exempt

from .models import Domain, User

# Create your views here.

SECRET_KEY='omo'

@csrf_exempt
def getToken(request):
    auth = request.headers['Authorization']
    if auth is not None:
        token = auth.split('Bearer ')[1]
        return token
    
    return None


@csrf_exempt
def index(request):
    token = getToken(request)
    data = jwt.decode(token, SECRET_KEY, ['HS256'])
    print(data)

    if (data['exp'] >= int(datetime.now(timezone.utc).timestamp())):
        return JsonResponse({"name": "fikky"})

    return JsonResponse({
        "message": "Unauthenticated",
    }, status = 403)




@csrf_exempt
def login(request):
    if request.method != 'POST':
        return HttpResponseBadRequest()

    email = request.POST.get('email')
    password = request.POST.get('password')

    try:
        user = User.objects.get(email=email)
        result = bcrypt.checkpw(password.encode('utf-8'), user.password)

        if result:
            json_data = {
                "user": user.id,
                "exp": (datetime.now(timezone.utc) + timedelta(hours=1))
            }

            token = jwt.encode(json_data, SECRET_KEY)

            return JsonResponse({
                "message": "Login successful",
                "token": token
            })
    except ObjectDoesNotExist:
        print("User record not found")
        return JsonResponse({"message": "User not found"}, status=404)


@csrf_exempt
def createworkspace(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=405)

    email = request.POST.get('email')
    password = request.POST.get('password')
    workspace_name = request.POST.get('workspace_name')
    phone = request.POST.get('phone')

    user = Domain()
    user.company_email = email
    user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user.company_name = workspace_name
    user.company_phone = phone

    json_data = {
        "user": user.id,
        "exp": (datetime.now() + timedelta(hours=1))
    }

    token = jwt.encode(payload=json_data, key=SECRET_KEY, algorithm="HS256")
    user.save()

    # link = "http://localhost:8000/api/signup " 

    return JsonResponse({
        "message": "Workspace created",
        "token": token,
        # "link": link
    },
                        status=200)

@csrf_exempt   # This is to disable the CSRF protection
def generateLink(request):


    json_data = {
                # "user": user.id,
                "exp": (datetime.now(timezone.utc) + timedelta(hours=1))
            }

    token = jwt.encode(json_data, SECRET_KEY)

    link = "http://localhost:8000/api/signup " + token

    return JsonResponse({ 
        "token": token,
        "link": link,
    })


@csrf_exempt
def signup(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    email = request.POST.get('email')
    password = request.POST.get('password')
    username = request.POST.get('username')

    first_name = request.POST.get('first_name')
    last_name = request.POST.get('last_name')
    middle_name = request.POST.get('middle_name')

    # domain = request.POST.get('domain')
    domain = 'startup'

    # try:
    user = User()

    user.email = email
    user.password = bcrypt.hashpw(password.encode('utf-8'),
                                    bcrypt.gensalt())
    user.username = username
    user.first_name = first_name
    user.last_name = last_name
    user.middle_name = middle_name

    user.domain = domain
    user.is_staff = True

    json_data = {
        "user": user.id,
        "exp": (datetime.now() + timedelta(hours=1))
    }

    token = jwt.encode(payload=json_data, key=SECRET_KEY, algorithm="HS256")
    user.save()

    return JsonResponse({
        "message": "User created",
        "token": token
    },
                        status=200)
    # except:
    #     return JsonResponse({"message": "An error occurred"}, status=500)