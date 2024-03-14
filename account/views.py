from django.shortcuts import render

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from .serializers import UserRegistrationSerializer
from .serializers import UserLoginSerializer
from .serializers import UserProfileSerializer
from .serializers import UserChangePasswordSerializer
from .serializers import SentResetPasswordEmailSerializer
from .serializers import UserPasswordResetSerializer

from django.contrib.auth import authenticate

from .renderers import UserRenderer

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

# Create JWT tokens manually

from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Create your views here.

class UserRegistration(APIView):

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):

        serializer = UserRegistrationSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # Create the user tokens and add it
            # to the response

            token = get_tokens_for_user(user)

            return Response({
                'token': token,
                'msg': 'You are registered successfully'
            }, status=status.HTTP_201_CREATED)
        
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class UserLogin(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data.get('password')

            user = authenticate(email=email, password=password)

            if user is not None:
                token = get_tokens_for_user(user)
                return Response({
                    'token': token,
                    'msg': 'Login Successful'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'errors': 'Email or Password are not valid'
                }, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfile(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UserChangePassword(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data,
            context={'user': request.user}
        )

        if serializer.is_valid():
            return Response({
                'msg': 'Password change successful'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SentResetPasswordEmail(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SentResetPasswordEmailSerializer(data=request.data)

        if serializer.is_valid():
            return Response({
                'msg': 'Password link sent to your email. Please click on the link to reset your password.'
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordReset(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data,
            context={
                'uid': uid,
                'token': token
            }
        )

        if serializer.is_valid():
            return Response({
                'msg': 'Password reset successful'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LogoutUser(APIView):
    def post(self, request, format=None):
        try:
            refresh_token = request.data.get('refresh_token')  
            token_obj = RefreshToken(refresh_token)
            token_obj.blacklist()
            return Response({
                'msg': 'You have logged out successfully'
            }, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)