from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.hashers import make_password
from rest_framework.utils import json
from rest_framework.views import APIView
import requests
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from authen.models import CustomUser
from django.contrib.auth.models import Group
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class GoogleView(APIView):

    @swagger_auto_schema(
            tags=['Auth'], 
            request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'token': openapi.Schema(type=openapi.TYPE_STRING, description='token'),
            }
        ))
    def post(self, request):
        payload = {"access_token": request.data.get("token")}
        r = requests.get("https://www.googleapis.com/oauth2/v2/userinfo", params=payload)
        data = json.loads(r.text)

        if "error" in data:
            content = {"message": "wrong google token / this google token is already expired."}
            return Response(content)
        try:
            user = CustomUser.objects.get(email=data["email"])
        except CustomUser.DoesNotExist:
            user = CustomUser()
            user.username = data["email"]
            user.password = make_password(BaseUserManager().make_random_password())
            user.email = data["email"]
            user.is_staff = True
            user.save()
            filtr_gr = Group.objects.filter(id=4)
            for i in filtr_gr:
                user.groups.add(i.id)

        token = RefreshToken.for_user(user)
        response = {}
        response["username"] = user.username
        response["access_token"] = str(token.access_token)
        response["refresh_token"] = str(token)
        return Response(response)