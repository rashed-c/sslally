from django.db import models

class CertMonitor(models.Model):    
    url = models.CharField(max_length=80)    
    certValid = models.BooleanField(default="False")
    expirationDate = models.CharField(max_length=80)   
    checkFrequency = models.IntegerField(default="86400")