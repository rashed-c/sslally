from multiprocessing import context
from django.shortcuts import render
import polls.views
from ratelimit.decorators import ratelimit
from ssl_monitor.models import CertMonitor #import database models


@ratelimit(key='ip', rate='1/m')
def home(request):
    
    url = "nessadc.com"
    certInfo = polls.views.CertInformation(url,"443")
    

    certs = CertMonitor()
    certs.url = url
    certs.checkFrequency = 3600
    certs.certValid = certInfo.getCertStatus()
    certs.expirationDate = certInfo.certExpirationDate
    certs.save()
    
    

    certObjs = CertMonitor.objects.all()

    context = {
        "cert_urls": certObjs
    }
    
       
    return render(request, 'polls/sslmonitor.html', context)
