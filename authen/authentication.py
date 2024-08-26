from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from authen.models import CustomUser

User = get_user_model()

class EmailOrUsernameModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get('username')
        if username is None or password is None:
            return
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
