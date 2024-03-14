from django.contrib import admin
from django.urls import path, include

from .views import UserRegistration
from .views import UserLogin
from .views import UserProfile
from .views import UserChangePassword
from .views import SentResetPasswordEmail
from .views import UserPasswordReset
from .views import LogoutUser

urlpatterns = [
    path('register/', UserRegistration.as_view(), name='register'),
    path('login/', UserLogin.as_view(), name='login'),
    path('profile/', UserProfile.as_view(), name='profile'),
    path('changepassword/', UserChangePassword.as_view(), name='changepassword'),
    path('reset-password/', SentResetPasswordEmail.as_view(), name='reset-password'),
    path('reset-password/<uid>/<token>/', UserPasswordReset.as_view(), name='user-reset-password'),
    path('logout/', LogoutUser.as_view(), name='logout'),
    
]