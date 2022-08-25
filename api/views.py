from __future__ import print_function
from datetime import datetime, timedelta, timezone
import email
from email import message
from os import environ
from telnetlib import STATUS
from django.http import Http404, HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import render
from django.http.response import JsonResponse, HttpResponse,HttpResponseBadRequest
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required

import bcrypt
import jwt

from django.views.decorators.csrf import csrf_exempt

# from bluetick.settings import RECIPIENT_ADDRESS

from .models import Domain, User, invitation
import random

from django.core.mail import send_mail
from django.conf import settings


# gmail imports

import base64
from email.message import EmailMessage

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# imports for otp
from lib2to3.pgen2.tokenize import generate_tokens
from django_otp.oath import TOTP
from django_otp.util import random_hex
from unittest import mock
import time
from itertools import chain
import json

from django.core.mail import EmailMessage

# Create your views here.

class TOTPVerification:
    
    def __init__(self):
        # secret key that will be used to generate a token,
        # User can provide a custom value to the key.
        self.key = bytes(random_hex(20), 'utf-8')
        # counter with which last token was verified.
        # Next token must be generated at a higher counter value.
        self.last_verified_counter = -1
        # this value will return True, if a token has been successfully
        # verified.
        self.verified = False
        # number of digits in a token. Default is 6
        self.number_of_digits = 6
        # validity period of a token. Default is 30 second.
        self.token_validity_period = 350

    def totp_obj(self):
        # create a TOTP object
        totp = TOTP(key=self.key,
                    step=self.token_validity_period,
                    digits=self.number_of_digits)
        # the current time will be used to generate a counter
        totp.time = time.time()
        return totp

    def generate_token(self):
        # get the TOTP object and use that to create token
        totp = self.totp_obj()
        # token can be obtained with `totp.token()`
        token = str(totp.token()).zfill(6)
        return token


    def verify_token(self, token, tolerance=0):
        try:
            # convert the input token to integer
            token = int(token)
        except ValueError:
            # return False, if token could not be converted to an integer
            self.verified = False
        else:
            totp = self.totp_obj()
            # check if the current counter value is higher than the value of
            # last verified counter and check if entered token is correct by
            # calling totp.verify_token()
            if ((totp.t() > self.last_verified_counter) and
                    (totp.verify(token, tolerance=tolerance))):
                # if the condition is true, set the last verified counter value
                # to current counter value, and return True
                self.last_verified_counter = totp.t()
                self.verified = True
            else:
                # if the token entered was invalid or if the counter value
                # was less than last verified counter, then return False
                self.verified = False
        return self.verified
SECRET_KEY= 'omo'

toke = TOTPVerification()


@csrf_exempt
def token_generation(email):
    """generate the token and send it to the user"""
# create the otp
# first send the otpto the email   
# def send_otp():

    generate_token = toke.generate_token()
    print(generate_token)
    
    # gmail_create_draft(content = 'token: ' + generate_token, emailto = user.company_email, emailfrom = 'fikayodan@gmail.com', emailsub = 'token')
    send_mail(
        'Bluetick',
        'token: ' + generate_token,
        'fikayodan@gmail.com',
        [email],
        fail_silently=False,
    )
    
    return  generate_token
    # return JsonResponse({
    #     "message": "Token generated"                      
    # },status=200)
#     token = request.POST.get('token')

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



# login in for every user both admin and user
@csrf_exempt
def login(request):
    if request.method != 'POST':
        return JsonResponse({
            "message": "Method not allowed"
        }, status = 405)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    email = body['email']
    password = body['password']

    # return JsonResponse({
    #     "omo": "user"
    # })
    if email is None or password is None:
        return JsonResponse({
            "message": "Missing credentials"
        }, status = 400)

    # get all the users by email
    # user_email_list = User.objects.values_list('email', flat=True)
    # workspace_email_list = Domain.objects.values_list('company_email', flat=True)

    # if email not in User.objects.values_list('email', flat=True) or email not in Domain.objects.values_list('company_email', flat=True):
    #     return JsonResponse({
    #         "message": "Invalid credentials"
    #     }, status = 401)
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

        return JsonResponse({
            "message": "Invalid email/password"
        }, status = 401)
        
    except ObjectDoesNotExist:
        print("User record not found")
        return JsonResponse({"message": "User not found"}, status=404)
# signing up a new workspace
@csrf_exempt
def createworkspace(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=405)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    # content = body['email']
    # return JsonResponse({"email": content})

    

    email = body['email']
    password1 = body['password1']
    password2 = body['password2']

    workspace = Domain.objects.values_list('company_email', flat=True)
    if email in workspace:
        return JsonResponse({"message": "Email already exists"}, status=400)

    

    if password1 != password2:
        return JsonResponse({"message": "Passwords do not match"}, status=400)
    workspace_name = body['workspace_name']


    phone = body['phone']


    work_name = Domain.objects.values_list('company_name', flat=True)
    if workspace_name in work_name:
        return JsonResponse({"message": "Workspace name already exists"}, status=400)

    # ensure user inputs all required fields
    # if email is None or password1 is None or workspace_name is None or phone is None:
    #     return JsonResponse({"message": "Missing required fields"}, status=400)
    
    user = Domain()

    # check if email already exists
    if email in Domain.objects.values_list('company_email', flat=True):
        return JsonResponse({"message": "Email already exists"}, status=400)

    # check if workspace name already exists
    if workspace_name in Domain.objects.values_list('company_name', flat=True):
        return JsonResponse({"message": "Workspace name already exists"},status=400)
    user.company_email = email
    user.password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
    user.company_name = workspace_name
    user.company_phone = phone

    # return JsonResponse({"message": "Workspace created"}, status=200)
    # return JsonResponse({"message": "Workspace created"})
    # json_data = {
    #     "user": user.id,
    #     "exp": (datetime.now() + timedelta(hours=1))
    # }

    # tokens = jwt.encode(payload=json_data, key=SECRET_KEY, algorithm="HS256")

    token = token_generation(user.company_email)
    # return JsonResponse({"message": "Workspace created"}, status=201)
    # return JsonResponse({
    #     "message": "Workspace created"
    # })

    # tok = token()
    # tok.email = user.company_email
    # tok.token = token
    # tok.save()


    # user.save()

    # send_mail(
    #     subject="Bluetick Workspace otp",
    #     message=otp,
    #     from_email=settings.EMAIL_HOST_USER,
    #     recipient_list=[user.company_email])
    # token_generation(request,"Bluetick account otp",user.company_email)


    # otp = request.POST.get('otp')
    # if otp == otp:
    #     user.save()
    #     return JsonResponse({
    #         "message": "Workspace created successfully",
    #         "token": tokens
    #     })
    # else:
    #     return JsonResponse({
    #         "message": "Invalid otp"
    #     }, status = 401)



    # link = "http://localhost:8000/api/signup " 
    user.save()

    return JsonResponse({
        "message": "Workspace created",
        "token": token,
    },
                        status=200)


# create ans send the otp to the user
# @csrf_exempt
# def sendotp()

#TODO generate invitation link
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


# signup a new staff and verify invitation link
@csrf_exempt
def signemail(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"}, status = 400)
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    email = body["email"]
    invitation_link = body["invitation_link"]


    emails_sent= invitation.objects.values_list('email', flat=True)
    all_sent = list(chain(emails_sent))

    # print(all_sent)

    if email not in all_sent:
        return JsonResponse({"message":"You have not been invited"})
    try:
        user = invitation.objects.get(email=email)
    except Exception as e:
        print(e)
    # print(user)
    print(user.email)

    # return JsonResponse({"message":"hello"})
    try:
        if user.invitation_link != invitation_link:
            return JsonResponse({"message":"invalid invitation link"}, status=403)
        else:
            user.delete()
            # delete the user and the link
        return JsonResponse({"message":"link correct"})
    except Exception as e:
        print(e)


    #TODO: create a new table that stores the invitation link with the corresponding email and check it with "signemail" funciton
@csrf_exempt
def addmem(request):
    if request.method != 'POST':
        return JsonResponse({"message":"Invalid Method"}, status = 400)
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    email_list = body["email_list"]
    workspacename = body["workspacename"]

    print(email_list)

    
    # return JsonResponse({"message":"rest"})

    for email in email_list:
        print("hello")
        
        new_toke = TOTPVerification()
        token = new_toke.generate_token()
        print(token)

        body = 'Copy the invitation link below\n'
        link ='https://'+email+'/?='+token
        
        # try:
        user = invitation.objects.filter(email=email).exists()
        print(user)
        # except Exception as e:
        #     print(e)


        # return JsonResponse({"message":"rest"}) 
        try:
            if user:
                us = invitation.objects.filter(email=email).update(invitation_link = link)
                if us == 1:
                    print("updated")
            else:
                invitee = invitation()

                invitee.email = email
                invitee.invitation_link = link
                invitee.workspacename = workspacename

                invitee.save()
                print(link)
        except Exception as e:
            print(e)
        try:
            send_mail(
                subject="Invitation to Join Workspace",
                message=body + link,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email])
        except Exception as e:
            print(e)

        # email = EmailMessage(
        #     subject="Invitation to Join Workspace",
        #     body=body + link,
        #     from_email=settings.EMAIL_HOST_USER,
        #     to=[email]
        # )
        # email.send()
        print("sent")

    # # for each member on the email list generate a special token and add something then save it in the database
    # # Then send it to the email
    return JsonResponse({"message":"member added"})  


# signup as a new user ie not admin/ workspace
@csrf_exempt
def signup(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)


    email = body['email']
    password1 = body['password1']
    password2 = body['password2']
    if password1 != password2:
        return JsonResponse({"message": "Passwords do not match"}, status=400)
    # username = request.POST.get('username')

    full_name = body['full_name']
    role = body['role']

    if email == None or password1 == None or full_name == None or role == None:
        return JsonResponse({"message": "Missing required fields"}, status=400)
    # last_name = request.POST.get('last_name')
    # middle_name = request.POST.get('middle_name')

    # check if email already exists
    if email in User.objects.values_list('email', flat=True):
        return JsonResponse({"message": "Email already exists"}, status=400)

    # check if full_name already exists
    if full_name in User.objects.values_list('full_name', flat=True):
        return JsonResponse({"message": "Full name already exists"}, status=400)

    # domain = request.POST.get('domain')
    domain = 'startup'

    # try:
    user = User()
    if email in User.objects.values_list('email', flat=True):
        return JsonResponse({"message": "Email already exists"}, status=400)
    

    user.email = email
    user.password = bcrypt.hashpw(password1.encode('utf-8'),
                                    bcrypt.gensalt())
    # user.username = username
    user.full_name = full_name
    user.role = role
    # user.last_name = last_name
    # user.middle_name = middle_name

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


# this is for the forgot password part of the app
reset = TOTPVerification()
@csrf_exempt
def resetpassword(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)
    return JsonResponse({"message": "Missing required fields"})

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    email = body['email']
    print(type(email))
    # if email == None:
    
    user = User.objects.get(email=email)

    if user:
        otp = reset.generate_token()
        send_mail(
            subject="Bluetick Workspace otp",
            message=otp,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email])
        # token_generation(request,"Bluetick account otp",user.email)

        return JsonResponse({
            "message": "Otp sent"
        },
                        status=200)
    else:
        return JsonResponse({
            "message": "User not found"
        },
                        status=404)

    # otp = reset.generate_token(email)


# sending the otp to the email i guess
    send_mail(
        subject="Reset password",
        message=otp,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[email])
    otp = request.POST.get('otp')

    
    password = request.POST.get('password')


    user = User.objects.get(email=email)

    if user:
        if user.otp == otp:
            user.password = bcrypt.hashpw(password.encode('utf-8'),
                                            bcrypt.gensalt())
            user.save()
            return JsonResponse({"message": "Password reset successfully"},
                                status=200)
        else:
            return JsonResponse({"message": "Invalid OTP"},
                                status=400)
    else:
        return JsonResponse({"message": "User not found"},
                            status=404)

def gmail_create_draft(content, emailto, emailfrom, emailsub):
    """Create and insert a draft email.
       Print the returned draft's message and id.
       Returns: Draft object, including draft id and message meta data.

      Load pre-authorized user credentials from the environment.
      TODO(developer) - See https://developers.google.com/identity
      for guides on implementing OAuth2 for the application.
    """
    creds, _ = google.auth.default()

    try:
        # create gmail api client
        service = build('gmail', 'v1', credentials=creds)

        message = EmailMessage()

        message.set_content(content)

        message['To'] = emailto
        message['From'] = emailfrom
        message['Subject'] = emailsub

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {
                'raw': encoded_message
        }
        # pylint: disable=E1101
        draft = service.users().drafts().create(userId="me",
                                                body=create_message).execute()

        print(F'Draft id: {draft["id"]}\nDraft message: {draft["message"]}')

    except HttpError as error:
        print(F'An error occurred: {error}')
        draft = None

    return draft


# request for the otp
# verify the otp
# if it is correct create the workspace

# a function for sending and verifying the OTP
@csrf_exempt
def token_verify(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)
                
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    token = body['token']
    # print(token)
    # add if the user is verified or not in the database
    email = body['email']
    if toke.verify_token(token):
        return JsonResponse({
            "message": "Token verified"
        },status=200)
    else:
        return JsonResponse({
            "message": "Invalid token"
        },status=400)
        
@csrf_exempt
def reset_verify(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    token = body['token']
    if reset.verify_token(token):
        
        return JsonResponse({
            "message": "Token verified"
        },status=200)
    else:
        return JsonResponse({
            "message": "Invalid token"
        },status=400)

    # return JsonResponse({"message": "Token verified"})
@csrf_exempt
def reset_password(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    email_ad = body['email']

    # print(type(email_ad))
    # print(email_ad)
    # user = User.objects.get(email=email_ad)


    password1 = body['password']
    password2 = body['password2']

    if password1 != password2:
        return JsonResponse({"message": "Passwords do not match"},
                            status=400) 
    
    # check if the email is in the user table
    work = Domain.objects.filter(company_email=email_ad).exists()
    # print(work)


    user = User.objects.filter(email = email_ad).exists()
    # print(user)
    
    
    

    # return JsonResponse({"message": "Password reset successfully"})
    # print(type(user))
    # check if the user is in the workspace(domain) table
    if user:
        us = User.objects.filter(email=email_ad).update(password = (bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())))
        # us.password = bcrypt.hashpw(password1.encode('utf-8'),
        #                                     bcrypt.gensalt())
        if us == 1:
            return JsonResponse({"message": "Password reset successfully"}, status=200)
        else:
            return JsonResponse({"message":"Password update unsuccessful"})
        

        # try:
        #     us.save()
        # except Exception as e:
        #     print(e)
        # print(user.password)
        return JsonResponse({"message": "Password reset successfully"},
                            status=200)
    elif work:
        wp = Domain.objects.filter(company_email = email_ad).update(password=(bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())))
        # work.password = bcrypt.hashpw(password1.encode('utf-8'),
        #                                     bcrypt.gensalt())
        # work.save()
        if wp == 1:
            return JsonResponse({"message": "Password reset successfully"},
                            status=200)
        else:
            return JsonResponse({"message":"Password update unsuccessful"})
    else:
        return JsonResponse({"message": "User not found"},
                            status=404)
    





# if __name__ == '__main__':
#     gmail_create_draft()

def getusers(request):
    users = User.objects.values_list('email', flat=True)
    workspace = Domain.objects.values_list('company_email', flat=True)
    # print(users)
    all_users = list(chain(users))
    print(all_users)
    all_workspace = list(chain(workspace))
    return JsonResponse({"all_users": all_users, "all_workspace": all_workspace},  status=200)

@csrf_exempt
def work_log(request):

    if request.method != 'POST':

        body = json.loads(request.body.decode('utf-8'))

        email = body['email']
        hours = body['work_hours']


