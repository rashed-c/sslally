from multiprocessing import context
from django.shortcuts import render
from ratelimit.decorators import ratelimit
from ssl_monitor.models import CertMonitor


@ratelimit(key='ip', rate='1/m')
def home(request):
    
    certs = CertMonitor()
    certs.url = 'nexon.net'
    certs.checkFreqency = 3600
    certs.save()

    certObjs = CertMonitor.objects.get(pk=11)
    

    context = {
        "cert_urls": certObjs.url
    }
    
       
    return render(request, 'polls/sslmonitor.html', context)
