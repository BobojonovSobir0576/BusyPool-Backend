from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import AuthenticationFailed

from django.core.validators import MinLengthValidator, MaxLengthValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail

from authen.models import CustomUser

from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model, authenticate


class UserGroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields = ['id', 'name']


class UserSignUpSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(validators=[UniqueValidator(queryset=CustomUser.objects.all())])
    username = serializers.CharField(required=True, max_length=20, validators=[UniqueValidator(queryset=CustomUser.objects.all()),
            MaxLengthValidator(limit_value=20, message="Username cannot exceed 20 characters.")],)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    groups = serializers.PrimaryKeyRelatedField(queryset=Group.objects.all(), many=True, required=False)

    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "last_name", "username", "email","password", "confirm_password", "groups"]

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as exc:
            raise serializers.ValidationError(str(exc))
        return value

    def create(self, validated_data):
        groups_data = validated_data.pop('groups', [])
        if validated_data["password"] != validated_data["confirm_password"]:
            raise serializers.ValidationError({"error": "Those passwords don't match"})
        validated_data.pop("confirm_password")
        create = CustomUser.objects.create_user(**validated_data)
        create.groups.set(groups_data)
        create.generate_verification_code()
        create.is_active = False
        self.send_verification_email(create)
        return create

    def send_verification_email(self, user):
            subject = 'Email Verification'
            message = f'Your verification code is: {user.verification_code}'
            from_email = 'istamovibrohim8@gmail.com'
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)


class UserUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True, max_length=20, validators=[UniqueValidator(queryset=CustomUser.objects.all()),
            MaxLengthValidator(limit_value=20, message="Username cannot exceed 20 characters.")],)
    avatar = serializers.ImageField(max_length=None, use_url=True)
    avatar = serializers.ImageField(max_length=None, allow_empty_file=False, allow_null=False, use_url=False, required=False,)
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=Group.objects.all(), required=False)

    class Meta:
        model = CustomUser
        fields = ["id", "username", "is_staff", "avatar", "groups"]

    def update(self, instance, validated_data):
        instance.username = validated_data.get("username", instance.username)
        instance.is_staff = validated_data.get("is_staff", instance.is_staff)
        if instance.avatar == None:
            instance.avatar = self.context.get("avatar")
        else:
            instance.avatar = validated_data.get("avatar", instance.avatar)
        if "groups" in validated_data:
            groups = validated_data.pop("groups")
            instance.groups.set(groups)
        instance.save()
        return instance


class UserSignInSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=50, min_length=2)
    password = serializers.CharField(max_length=50, min_length=1)

    class Meta:
        model = CustomUser
        fields = ["username", "password"]
        read_only_fields = ("username",)

    def validate(self, data):
        if self.context.get("request") and self.context["request"].method == "POST":
            allowed_keys = set(self.fields.keys())
            input_keys = set(data.keys())
            extra_keys = input_keys - allowed_keys
            if extra_keys:
                raise serializers.ValidationError(f"Additional keys are not allowed: {', '.join(extra_keys)}")
        return data


class UserInformationSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(max_length=None, use_url=True)
    groups = UserGroupSerializer(many=True, read_only=True)

    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "is_staff", "avatar", "groups"]


class ChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        """
        Check if new_password matches confirm_password.
        """
        if data.get('new_password') != data.get('confirm_password'):
            raise serializers.ValidationError("The new password and confirm password must match.")
        return data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ["email"]


class PasswordResetCompleteSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=32, write_only=True)
    confirm_password = serializers.CharField(min_length=8, max_length=32, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "token", "uidb64"]

    def validate(self, attrs):
        password = attrs.get("password")
        confirm_password = attrs.get("confirm_password")
        token = attrs.get("token")
        uidb64 = attrs.get("uidb64")

        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("Invalid link", 401)

            user.set_password(password)
            user.save()
            return user
        except Exception:
            raise AuthenticationFailed("Invalid link", 401)
        

    
class OwnerSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(max_length=None, use_url=True)
    groups = UserGroupSerializer(many=True, read_only=True)

    class Meta:
        model = CustomUser
        fields = ["id", "username", "avatar", "email", "groups"]