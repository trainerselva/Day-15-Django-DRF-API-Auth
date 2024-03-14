from rest_framework import serializers
from .models import User

from xml.dom import ValidationErr
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from .utils import Util

class UserRegistrationSerializer(serializers.Serializer):
    
    password2 = serializers.CharField(style={'input-type', 'password'}, write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'name', 'remember_me', 'password', 'password2']
        extra_kwargs={
            'password': {'write_only': True}
        }
    
    def validate(self, attrs):
        
        print('attrs: ', attrs)

        password = attrs.get('password')
        password2 = attrs.get('password2')
        
        if password != password2:
            raise serializers.ValidationError('Password and confirm password do not match')
        
        return attrs
    
    def create(self, validated_data):
        print('Validated data: ', validated_data)
        return User.objects.create_user(**validated_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email", "name"]


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )
    password2 = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )

    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError('Password and Confirm password do not match')
        
        user.set_password(password)
        user.save()

        return attrs
    


class SentResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID: ', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password reset token: ', token)
            link = 'http://localhost:3000/api/reset/' + uid + '/' + token
            print('Password reset link: ', link)
            return attrs
        else:
            raise ValidationErr('You are not a registered user')

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )    
    password2 = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )

    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')

            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError('Password and Confirm password do not match')
            
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID: ', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password reset token: ', token)
            link = 'http://localhost:3000/api/reset/' + uid + '/' + token

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is either invalid or expired')
            
            user.set_password(password)
            user.save()

            body = 'Click the following link to Reset your password' + link
            data = {
                'subject': 'Reset your password',
                'body': body,
                'to_email': user.email
            }

            Util.send_email(data)

            return attrs
        
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('The token is either invalid or expired')