from django.urls import path
from authen.google import GoogleView
from authen.views import (
    UserSignUp,
    UserSignIn,
    UserProfile,
    change_password,
    RequestPasswordRestEmail,
    SetNewPasswordView,
    UserGroupView,
    VerifyEmail,
)

urlpatterns = [
    path('google/', GoogleView.as_view(), name='google_login'),
    path('user/roll/', UserGroupView.as_view()),
    path('register/', UserSignUp.as_view()),
    path('verification/email/', VerifyEmail.as_view()),
    path('login/', UserSignIn.as_view()),
    path('profile/', UserProfile.as_view()),
    path('password/change/', change_password),
    path('password/rest/', RequestPasswordRestEmail.as_view()),
    path('password/new/', SetNewPasswordView.as_view()),

]