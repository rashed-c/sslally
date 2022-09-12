from django.db import models

class CertMonitor(models.Model):    
    url = models.CharField(max_length=80)    
    certStatus = models.CharField(max_length=80)
    checkFreqency = models.IntegerField(default="86400")