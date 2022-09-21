# Bluetick API
## This API is used for the bluetick app

### [api](Bluetick-backend/api)
- contains the python api files.
1. [__init__.py](/Bluetick-backend/api/__init__.py) : makes the api directory a module
2. [models.py](/Bluetick-backend/api/models.py): used to create models:
  - the "User" model, which is used to make users
  - the "Log" model, which is used to make the login and logout features
3. [urls.py](/Bluetick-backend/api/urls.py) : defines the path that connects us to our login, signup and index views
4. [views.py](/Bluetick-backend/api/views.py) : this is where our signup, login, token generation and index functions are defined
5. [migrations](/Bluetick-backend/api/migrations) : two migrations so far for the bluetick api

### [bluetick](/Bluetick-backend/bluetick)
- Django project, implements the api app
1. [__init__.py](/Bluetick-backend/bluetick/__init__.py) : makes the api directory a module
2. [asgi.py](/Bluetick-backend/bluetick/asgi.p): would be used for the app chat function
> asgi.py functions is not yet implemented
3. [settings.py](/Bluetick-backend/bluetick/settings.py) : All applications, security modules and databases are registered here
4. [urls.py](/Bluetick-backend/bluetick/urls.py) : used to connect the api app urls to the django project

### [manage.py](/Bluetick-backend/manage.py) 
- used for executing django specific tasks.

### [requirements.txt](/Bluetick-backend/requirements.txt) 
- contains all the dependencies needed to run the django app 

## Steps to use this Django App
- clone the project : git clone https://github.com/BluetickNG/Bluetick-backend.git
- get all the dependencies using : pip install requirements.txt (a virltual environment can be used depending on your preference)
- make your migrations using: python3 manage.py makemigrations 
- use and implement the api using postman, Enjoy :tada:

## This project is open to contributions by anyone willing to make meaningful contributions to the project


