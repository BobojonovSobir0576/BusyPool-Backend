from django.db import models
from django.contrib.auth.models import AbstractUser
import random
import string


class CustomUser(AbstractUser):
    avatar = models.ImageField(upload_to='avatar/', null=True, blank=True)
    phone = models.CharField(max_length=250, null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    url_profile = models.URLField(null=True, blank=True)
    city = models.CharField(max_length=250)
    about_me = models.TextField(null=True, blank=True)
    verification_code = models.CharField(max_length=250, null=True, blank=True)
    is_active = models.BooleanField(default=False)

    def generate_verification_code(self):
        """Tasodifiy 6 xonali kod generatsiya qiladi"""
        self.verification_code = ''.join(random.choices(string.digits, k=6))
        self.save()
