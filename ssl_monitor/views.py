from multiprocessing import context
from django.shortcuts import render
from ratelimit.decorators import ratelimit
from ssl_monitor.models import CertMonitor #import database models


@ratelimit(key='ip', rate='1/m')
def home(request):
    
    certs = CertMonitor()
    certs.url = 'nexon.net'
    certs.checkFreqency = 3600
    certs.save()

    certObjs = CertMonitor.objects.all()
    
    

    context = {
        "cert_urls": certObjs
    }
    
       
    return render(request, 'polls/sslmonitor.html', context)
