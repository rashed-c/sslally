from django.db import models
from django.contrib.auth.models import User

class CertMonitor(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,)
    url = models.CharField(max_length=80)    
    certValid = models.BooleanField(default="False")
    expirationDate = models.CharField(max_length=80)   
    checkFrequency = models.IntegerField(default="86400")