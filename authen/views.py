from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import authenticate
from django.contrib.auth import update_session_auth_hash

from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_encode

from rest_framework import generics
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import action

from django.core.mail import send_mail
from django.utils.encoding import smart_bytes
from utils.renderers import UserRenderers
from utils.utils import Util
from utils.permissions import IsLogin
from utils.expected_fields import check_required_key
from utils.response import (
    bad_request_response,
    success_created_response,
    success_response,
    user_not_found_response
)

from authen.models import CustomUser
from authen.serializers import (
    UserSignUpSerializer,
    UserSignInSerializer,
    UserInformationSerializer,
    UserUpdateSerializer,
    ChangePasswordSerializer,
    ResetPasswordSerializer,
    PasswordResetCompleteSerializer,
    UserGroupSerializer
)


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token)}


class UserGroupView(APIView):

    @swagger_auto_schema(tags=['Auth'], responses={200: UserGroupSerializer(many=True)})
    def get(self, request):
        group = Group.objects.all()
        serializer = UserGroupSerializer(group, many=True)
        return success_response(serializer.data)

class UserSignUp(APIView):
    render_classes = [UserRenderers]

    @swagger_auto_schema(tags=['Auth'], request_body=UserSignUpSerializer)
    def post(self, request):
        serializer = UserSignUpSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            instanse = serializer.save()
            return success_created_response("Verification email sent. Please check your inbox.")
        return bad_request_response(serializer.errors)        


class VerifyEmail(APIView):

    @swagger_auto_schema(
        tags=['Auth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'code': openapi.Schema(type=openapi.TYPE_STRING, description='code'),
            }
        )
    )
    def post(self, request):
        code = request.data.get('code')
        try:
            user = CustomUser.objects.get(verification_code=code)
            if user.is_active:
                return bad_request_response("User is already verified.")
            user.is_active = True
            user.verification_code = None
            user.save()
            tokens = get_token_for_user(user)
            return success_response(tokens)
        except CustomUser.DoesNotExist:
            return bad_request_response("Invalid verification code.")


class UserSignIn(APIView):
    renderer_classes = [UserRenderers]

    @swagger_auto_schema(tags=['Auth'], request_body=UserSignInSerializer)
    def post(self, request):
        serializer = UserSignInSerializer(data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            username = request.data["username"]
            password = request.data["password"]
            user = authenticate(username=username, password=password)

            if user is not None:
                if not user.is_active:
                    return bad_request_response("Your account has been blocked.")
                tokens = get_token_for_user(user)
                return success_created_response(tokens)
            else:
                # User not found; handle verification code generation and email sending
                try:
                    # Attempt to retrieve the user by username (assuming email or phone number)
                    user = CustomUser.objects.get(username=username)
                    user.generate_verification_code()

                    subject = 'Email Verification'
                    message = f'Your verification code is: {user.verification_code}'
                    from_email = 'istamovibrohim8@gmail.com'
                    recipient_list = [user.email]
                    send_mail(subject, message, from_email, recipient_list)

                    return user_not_found_response("Verification code sent to your email.")
                except CustomUser.DoesNotExist:
                    return user_not_found_response("User not found.")

        return success_created_response(serializer.errors)


class UserProfile(APIView):
    render_classes = [UserRenderers]
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsLogin]

    @swagger_auto_schema(tags=['Auth'], responses={200: UserInformationSerializer(many=True)})
    def get(self, request):
        serializer = UserInformationSerializer(request.user, context={"request": request})
        return success_response(serializer.data)
    

    @swagger_auto_schema(tags=['Auth'], request_body=UserUpdateSerializer)
    def put(self, request, *args, **kwarg):
        queryset = get_object_or_404(CustomUser, id=request.user.id)
        serializer = UserUpdateSerializer(context={"request": request}, instance=queryset, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return success_response(serializer.data)
        return bad_request_response(serializer.errors)

    @swagger_auto_schema(tags=['Auth'], responses={204:  'No Content'})
    def delete(self, request):
        user_delete = CustomUser.objects.get(id=request.user.id)
        user_delete.delete()
        return success_response("delete success")


@api_view(["POST"])
@swagger_auto_schema(
        tags=['Auth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='new_password'),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, description='confirm_password'),
            }
        )
    )
@permission_classes([IsAuthenticated])
@permission_classes([IsLogin])
def change_password(request):
    if request.method == "POST":
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.data.get("new_password"))
            user.save()
            update_session_auth_hash(request, user)
            return success_response("Password changed successfully.")
        return bad_request_response(serializer.errors)


class RequestPasswordRestEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    @swagger_auto_schema(tags=['Forget Password'], request_body=ResetPasswordSerializer)
    @action(methods=['post'], detail=False)
    def post(self, request):
        email = request.data.get("email")
        if CustomUser.objects.filter(email=email).exists():
            user = CustomUser.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            absurl = f"https://mineplugins.com/reset-password/{uidb64}/{token}"
            email_body = f"Hi \n Use link below to reset password \n link: {absurl}"
            data = {
                "email_body": email_body,
                "to_email": user.email,
                "email_subject": "Reset your password",
            }

            Util.send(data)

            return success_response("We have sent you to rest your password")
        return user_not_found_response("This email is not found.")



class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = PasswordResetCompleteSerializer

    @swagger_auto_schema(tags=['Forget Password'], request_body=PasswordResetCompleteSerializer)
    @action(methods=['patch'], detail=False)
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return success_response("success.")
    