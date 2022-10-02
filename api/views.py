from __future__ import print_function
from datetime import datetime, timedelta, timezone
import email
from email import message
from os import environ
from telnetlib import STATUS
from xml import dom
from django.http import Http404, HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import render
from django.http.response import JsonResponse, HttpResponse,HttpResponseBadRequest
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import auth

import bcrypt
import jwt


from django.views.decorators.csrf import csrf_exempt

# from bluetick.settings import RECIPIENT_ADDRESS

from .models import  invitation, Worklog, Domain, User 
import random

from django.core.mail import send_mail
from django.conf import settings


# gmail imports

import base64
from email.message import EmailMessage

# import google.auth
# from googleapiclient.discovery import build
# from googleapiclient.errors import HttpError

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
        self.token_validity_period = 300

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
    # send_mail(
    #     'Bluetick',
    #     'token to verify workspace: ' + generate_token,
    #     settings.EMAIL_HOST_USER,
    #     [email],
    #     fail_silently=False,
    # )
    
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
    # return JsonResponse({"hello"})
    if request.method != 'POST':
        return JsonResponse({
            "message": "Method not allowed"
        }, status = 405)

    body_unicode = request.body.decode('utf-8')
    # print(body_unicode[1])
    body = json.loads(body_unicode)
    # b = request.get_json()
    try:
        email = body['email']
        raw_password = body['password']
    except:
        return JsonResponse({"message":"Invalid or incomplete credentials"}, status = 400)

    # if email is None or password is None:
    #     return JsonResponse({
    #         "message": "Missing credentials"
    #     }, status = 400)
    # return JsonResponse({"message":"done"})
    try:
        user = User.objects.get(email=email)
        workspace = user.domain
    except:
        return JsonResponse({
            "message":"Invalid Email"
        })
    if Domain.objects.get(company_email=email).verified is False:
        return JsonResponse({"message":"Acces Denied, Account not verified"})
    # byte_pass = password.encode('utf-8')
    # byte_pass = bytes(password.encode('utf-8'))
    # print(type(byte_pass))
    # print(type(password))
    print(raw_password)
    print(user.password)

    result = user.check_password(raw_password)
    print(result)
    # result = bcrypt.checkpw(byte_pass, user.password)
    # result = True

    if result:
        json_data = {
            "user": user.id,
            "email":user.email,
            "workspace":user.domain,
            "exp": (datetime.now(timezone.utc) + timedelta(hours=1))
        }
        User.objects.filter(email=email).update(is_online=True)
        token = jwt.encode(json_data, SECRET_KEY)
        is_admin = user.is_superuser

        if user.is_superuser == False and user.is_staff == True:
            isstaff = True
        else:
            isstaff = False

        return JsonResponse({
            "message": "Login successful",
            "workspacename":workspace,
            "is_admin":is_admin,
            # "is_staff":isstaff,
        
            "token": token
        })

    return JsonResponse({
        "message": "Invalid email/password",
        # "token":token
    }, status = 401)
                                    
    # except:
    #     print("User record not found")
    #     return JsonResponse({"message": "User not found"}, status=404)
# signing up a new workspace
@csrf_exempt
def createworkspace(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=405)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    # content = body['email']
    # return JsonResponse({"email": content})

    
    try:
        email = body['email']
        password1 = body['password1']
        password2 = body['password2']
        phone = body['phone']
        workspace_name = body['workspace_name']
    except:
        return JsonResponse({"message":"Invalid or incomplete credentials"}, status = 400)

    workspace = Domain.objects.values_list('company_email', flat=True)
    # user = User.objects.values_list('email', flat=True)

    users = User.objects.values_list('email', flat=True)
    if email in workspace:
        return JsonResponse({"message": "Email already exists"}, status=400)
    elif email in users:
        return JsonResponse({"message": "Email already exists"}, status=400)


    

    if password1 != password2:
        return JsonResponse({"message": "Passwords do not match"}, status=400)




    work_name = Domain.objects.values_list('company_name', flat=True)
    if workspace_name in work_name:
        return JsonResponse({"message": "Workspace name already exists"}, status=400)

    # ensure user inputs all required fields
    # if email is None or password1 is None or workspace_name is None or phone is None:
    #     return JsonResponse({"message": "Missing required fields"}, status=400)
    
    user = Domain()
    setuser = User()
    # return JsonResponse({"message":"done"})

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

    token = token_generation(user.company_email)

    setuser.full_name = workspace_name
    setuser.email = email
    setuser.role = "admin"
    setuser.domain = workspace_name
    setuser.set_password(password1)
    setuser.is_superuser = True
    setuser.is_staff = True
    
    # try:
    user.save()
    setuser.save()
    # except:
    #     return JsonResponse({"message":"save issue"})
    return JsonResponse({
        "message": "Workspace created",
        "token": token,
    },
                        status=200)

# signup a new staff and verify invitation link
@csrf_exempt
def signemail(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"}, status = 400)
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    try:
        email = body["email"]
        invitation_link = body["invitation_link"]
    except Exception as e:
        print(e)
        return JsonResponse({"message":"Invalid or incomplete credentials"}, status = 400)

    emails_sent= invitation.objects.values_list('email', flat=True)
    all_sent = list(chain(emails_sent))
    print(all_sent)
    # print(all_sent)

    # if email not in all_sent:
    #     return JsonResponse({"message":"You have not been invited"})
    try:
        user = invitation.objects.get(email=email)
    except Exception as e:
        print(e)
    # print(user)
    print(user.email)
    workspacename = user.workspacename
    # return JsonResponse({"message":"hello"})
    try:
        if user.invitation_link != invitation_link:
            return JsonResponse({"message":"invalid invitation link"}, status=403)
        # else:
            # user.delete()
            # delete the user and the link
        return JsonResponse({"message":"link correct", "workspace name":workspacename})
    except Exception as e:
        print(e)


    #TODO: create a new table that stores the invitation link with the corresponding email and check it with "signemail" funciton
@csrf_exempt
def addmem(request):
    if request.method != 'POST':
        return JsonResponse({"message":"Invalid Method"}, status = 400)
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    try:
        email_list = body["email_list"]
        workspacename = body["workspacename"]
    except:
        return JsonResponse({"message":"Invalid or incomplete credentials"}, status = 400)

    print(email_list)

    workspace = Domain.objects.values_list('company_email', flat=True)
    workspacenames = Domain.objects.values_list('company_name', flat=True)

    if workspacename not in workspacenames:
        return JsonResponse({"message":"workspace does not exist"}, status=400)
    # if the  email is already a workspace email return error
    # return JsonResponse({"message":"rest"})
    link_list = []
    for email in email_list:
        print("hello")
        if email in workspace:
            return JsonResponse({"message": email + " already in system"}, status=400)
            

        new_toke = TOTPVerification()
        token = new_toke.generate_token()
        print(token)

        body = 'Copy the invitation link below\n'
        link ='https://'+email+'/?='+token
        
        link_list.append(link)
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
        # try:
        #     send_mail(
        #         subject="Invitation to Join Workspace",
        #         message=body + link,
        #         from_email=settings.EMAIL_HOST_USER,
        #         recipient_list=[email])
        # except Exception as e:
        #     print(e)

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
    return JsonResponse({"message":"member added", "link":link_list}, status=200)  


# signup as a new user ie not admin/ workspace
@csrf_exempt
def signup(request):
    # return JsonResponse({"hello"})
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    try:
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)

        try:
            email = body['email']
            password1 = body['password1']
            password2 = body['password2']
            full_name = body['full_name']
            role = body['role']
        except:
            return JsonResponse({"message":"Invalid or incomplete credentials"}, status = 400)

        try:
            invi = invitation.objects.get(email=email)
            workspacename = invi.workspacename
        except Exception as e:
            print(e)
            return JsonResponse({"message":"You have not been invited"}, status=400)

        if password1 != password2:
            return JsonResponse({"message": "Passwords do not match"}, status=400)
        # username = request.POST.get('username')

    
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
        

        domain = workspacename

        # try:
        user = User()
        if email in User.objects.values_list('email', flat=True):
            return JsonResponse({"message": "Email already exists"}, status=400)
        

        user.email = email
        # user.password = bcrypt.hashpw(password1.encode('utf-8'),
        #                                 bcrypt.gensalt())
        # user.username = username
        user.set_password(password1)
        user.full_name = full_name
        user.role = role
        # user.last_name = last_name
        # user.middle_name = middle_name

        user.domain = domain
        user.is_staff = True

        # return JsonResponse({"message":"Hello"})
        json_data = {
            "user": user.id,
            "exp": (datetime.now() + timedelta(hours=1))
        }

        token = jwt.encode(payload=json_data, key=SECRET_KEY, algorithm="HS256")
        try:
            user.save()
        except Exception as e:
            print(e)
            return JsonResponse({"wahala"})


        return JsonResponse({
            "message": "User created",
            "token": token
        },
                            status=200)
    except Exception as e:
        print(e)
        return JsonResponse({"message": "An error occurred"}, status=500)


# this is for the forgot password part of the app
reset = TOTPVerification()

@csrf_exempt
def forgotpassword(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid method. Not allowed"})
    body = json.loads(request.body.decode('utf-8'))
    try:
        email = body['email']
    except:
        return JsonResponse({"message":"Incomplete or incorrect credentials"})
    if User.objects.get(email=email).is_online == False:
        return JsonResponse({"message":"permission denied. Login!"}, status=403)
    # check if the email is in the database
    if User.objects.filter(email=email).exists() or Domain.objects.filter(company_email=email).exists():
    
        token = reset.generate_token()

        # send_mail(
        #     subject="Reset password",
        #     message=token,
        #     from_email=settings.EMAIL_HOST_USER,
        #     recipient_list=[email])

        return JsonResponse({"message":"Token sent to mail","token":token})
    else:
        return JsonResponse({"message":"User does not exist"})
# a function for  verifying the OTP for creating a workspace
@csrf_exempt
def token_verify(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)
                
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    try:
        token = body['token']
        email = body['email']
    except:
        return JsonResponse({"message":"Invalid or incomplete credentials"}, status = 400)

    # if User.objects.get(email=email).is_online == False:
    #     return JsonResponse({"message":"permission denied. Login!"}, status=403)
    # print(token)
    # add if the user is verified or not in the database
    if toke.verify_token(token):
        verified = Domain.objects.filter(company_email=email).update(verified=True)
        return JsonResponse({
            "message": "Token verified"
        },status=200)
    else:
        # Domain.objects.filter(company_email=email).delete()
        try:
            user = User.objects.filter(email=email).delete()
            print(user)
            Domain.objects.get(company_email=email).delete()
        except:
            return JsonResponse({
                "message":"deleted"
            })

        # User.objects.get(email=email).delete()
        # delete the data from the database 
        return JsonResponse({
            "message": "Invalid token"
        },status=400)

# verify otp for resetting password
@csrf_exempt
def reset_verify(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    token = body['token']
    email = body['email']

    if User.objects.get(email=email).is_online == False:
        return JsonResponse({"message":"permission denied. Login!"}, status=403)

    if reset.verify_token(token):
        # set the pas_reset to true
        if User.objects.filter(email=email).exists():
            User.objects.filter(email=email).update(pas_reset=True)
        elif Domain.objects.filter(email=email).exists():
            Domain.objects.filter(email=email).update(pas_reset=True)
        return JsonResponse({
            "message": "Token verified"
        },status=200)
    else:
        return JsonResponse({
            "message": "Invalid token"
        },status=400)

    # return JsonResponse({"message": "Token verified"})

# Reset password of either user or workspace
@csrf_exempt
def reset_password(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    email_ad = body['email']

    if User.objects.get(email=email_ad).is_online == False:
        return JsonResponse({"message":"permission denied. Login!"}, status=403)
    # print(type(email_ad))
    # print(email_ad)
    # user = User.objects.get(email=email_ad)


    password1 = body['password']
    password2 = body['password2']


    if password1 != password2:
        return JsonResponse({"message": "Passwords do not match"},
                            status=400) 
    
    # check if the person has verified a token by pas_reset
    user_main = User.objects.get(email=email_ad)
    if user_main.pas_reset == True:

        # check if the email is in the user table
        work = Domain.objects.filter(company_email=email_ad).exists()
        # print(work)


        user = User.objects.filter(email = email_ad).exists()
        # print(user)
        
        
        

        # return JsonResponse({"message": "Password reset successfully"})
        # print(type(user))
        # check if the user is in the workspace(domain) table
        if user:
            user_main = User.objects.get(email=email_ad)
            if user_main.pas_reset == True:
                # us = User.objects.filter(email=email_ad).update(password = (bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())))
                # User.objects.filter(email=email_ad).update(password=password1)
                user_main.set_password(password1)
                user_main.save()
                us = True

                # us.password = bcrypt.hashpw(password1.encode('utf-8'),
                #                                     bcrypt.gensalt())
                if us == 1:
                    User.objects.filter(email=email_ad).update(pas_reset = False)
                    return JsonResponse({"message": "Password reset successfully"}, status=200)
                else:
                    return JsonResponse({"message":"Password update unsuccessful"})
            else:
                return JsonResponse({"message":"cannot reset password"}, status=400)
        
        elif work:
            domain_main = Domain.objects.get(email=email_ad)
            if domain_main.pas_reset == True:
                wp = Domain.objects.filter(company_email = email_ad).update(password=(bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())))
                # work.password = bcrypt.hashpw(password1.encode('utf-8'),
                #                                     bcrypt.gensalt())
                # work.save()
                if wp == 1:
                    Domain.objects.filter(email=email_ad).update(pas_reset = False)
                    return JsonResponse({"message": "Password reset successfully"},
                                    status=200)
                else:
                    return JsonResponse({"message":"Password update unsuccessful"})
            else:
                return JsonResponse({"message":"cannot reset password"}, status=400)
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
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)

    body = json.loads(request.body.decode('utf-8'))

    try:
        email = body['email']
        clockin = body['clockin_time']
        clockout = body['clockout_time']
        workspacename = body['workspacename']
        date = body['date']
    except:
        return JsonResponse({"message":"Invalid or inclomplete credentials"})

    log = Worklog()

    log.email = email
    log.clockintime = clockin
    log.clockouttime = clockout
    log.date = date
    log.workspace = workspacename
    # log.workhour = clockout - clockin


    
    # get the clock in time and date, the clock out time, then calculate the amount of hours worked


# get all the information of a particular user
@csrf_exempt
def getdetails(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)
    body = json.loads(request.body.decode('utf-8'))

    try:
        email = body['email']
    except:
        return JsonResponse({"message":"invalid or incomplete credentials"})

    try:
        user = User.objects.get(email=email)

        user_details = {
            "id":user.id,
            "email":user.email,
            "role":user.role,
            # "is_admin":user.is_admin,
            "is_staff":user.is_staff,
            "is_admin":user.is_superuser,
            "workspace":user.domain,
            "fullname":user.full_name,
            "is_online":user.is_online,
            # the image field should just be like a url
            "profileimg":user.profile_img.url

        }
        return JsonResponse({"details":user_details})
    except:
        return JsonResponse({"message":"User doesn't exist"})
# get all the staff in a particular workspace
@csrf_exempt
def getstaffs(request):
    if request.method != 'POST':
        return JsonResponse({"message": "Invalid Method. Not Allowed"},
                            status=400)
    body = json.loads(request.body.decode('utf-8'))

    try:
        workspacename = body['workspacename']
    except:
        return JsonResponse({"message":"invalid or incomplete credentials"})

    try:
        user = User.objects.filter(domain=workspacename)
        print(user)
        all_staff_details = []
        number_of_staffs = 0
        for each in user:
            user_details = {
            "id":each.id,
            "email":each.email,
            "role":each.role,
            # "is_admin":each.is_admin,
            "is_staff":each.is_staff,
            "is_admin":each.is_superuser,
            "workspace":each.domain,
            "fullname":each.full_name,
            # the image field should just be like a url
            "profileimg":each.profile_img.url
            }
            all_staff_details.append(user_details)
            number_of_staffs+=1
            # print(each.email)
        # print(all_staff_details)
        return JsonResponse({"staff number":number_of_staffs, "all staff details":all_staff_details})
    except Exception as e:
        print(e)
        return JsonResponse({"message":"workspace does not exist"})
# generate a csv file from the information from the database and send it to the admin at the end of the day or it can just be generated

@csrf_exempt
def workspacedetails(request):
    if request.method != 'POST':
        return JsonResponse({"message":"Invalid method, Method not allowed"}, status=400)

    body = json.loads(request.body.decode('utf-8'))

    try:
        email = body['email']
    except:
        return JsonResponse({"message":"invalid or incomplete credentials"})

    try:
        user = Domain.objects.get(company_email=email)

        user_details = {
            "id":user.id,
            "company email":user.company_email,
            "is_admin":user.is_admin,
            "is_staff":user.is_staff,
            "workspace phone":user.company_phone,
            "company name":user.company_name,
            "verified":user.verified,
            # the image field should just be like a url
            "profileimg":user.Workspace_profile_img.url

        }
        return JsonResponse({"details":user_details})
    except Exception as e:
        print(e)
        return JsonResponse({"message":"Workspace doesn't exist"})

# @csrf_exempt
def getallworkspace(request):

    
    try:
        # user = Domain.objects.filter(company_name=workspacename)
        user = Domain.objects.all()
       
        
        all_staff_details = []
        number_of_staffs = 0
        for each in user:
            print("1")
            user_details = {
            "id":each.id,
            "company email":each.company_email,
            "is_admin":each.is_admin,
            "is_staff":each.is_staff,
            "workspace phone":each.company_phone,
            "company name":each.company_name,
            # the image field should just be like a url
            "profileimg":each.Workspace_profile_img.url
            }
            all_staff_details.append(user_details)
            number_of_staffs+=1
            # print(each.company_email)
        print(all_staff_details)
        return JsonResponse({"Total number of workspaces":number_of_staffs, "all workspace details":all_staff_details})
    except Exception as e:
        print(e)
        return JsonResponse({"message":" workspace does not exist"})

def deleter(request):
    User.objects.all().delete()
    Domain.objects.all().delete()
    invitation.objects.all().delete()

    
    return JsonResponse({"message":"deleted"})

# @login_required()
@csrf_exempt
def logout(request):
    body = json.loads(request.body.decode('utf-8'))
    email = body["email"]
    # auth.logout(request)
    user= User.objects.get(email=email)
    user.is_online = False
    user.save()
    return (JsonResponse({"message":"User logged out"}))


@csrf_exempt
def upload(request):
    if request.method != 'POST':
        return JsonResponse({"Invalid Method, Method not allowed"}, status=400)
    # body = json.loads(request.body.decode('utf-8'))
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    try:
        thumbnail = request.FILES
    except Exception as e:
        print(e)
        return JsonResponse({"Invad"})
        
    # info = json.loads(request.data['email'])
    email = body["email"]
    print(body)

    work = User.objects.filter(email=email).update(profile_img=thumbnail)
    print(work)
    user = User.objects.get(email=email)

    # user.profile_img = thumbnail
    user.save()

    
    return JsonResponse({"message":"successful"})


    # user.profile_img = thumbnail

@csrf_exempt
def search(request):
    if request.method != 'POST':
        return JsonResponse({"Message":"Invalid Method, Method not allowed"}, status=400)
    body = json.loads(request.body.decode('utf-8'))

    name = body['name']
    full_name_obj = User.objects.filter(full_name__icontains=name)

    profiles = []

    for user in full_name_obj:
        info = {
            "full_name": user.full_name,
            "role": user.role

        }
        profiles.append(info)

    # profile_list = list(chain(*profiles))

    return JsonResponse({"profiles":profiles})
