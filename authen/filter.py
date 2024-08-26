from django_filters import rest_framework as filters
from django import forms
from authen.models import CustomUser
from django.db.models import Q



class UserFilter(filters.FilterSet):
    username = filters.CharFilter(field_name='username', lookup_expr='icontains')
    class Meta:
        model = CustomUser
        fields = ['username']