from http.client import HTTPResponse
from django.http import JsonResponse
from multiprocessing import context
from django.shortcuts import render
import polls.views
import json 
from ratelimit.decorators import ratelimit
from ssl_monitor.models import CertMonitor #import database models


@ratelimit(key='ip', rate='1/m')
def home(request):
    
    """  url = "nessadc.com"
    certInfo = polls.views.CertInformation(url,"443")
    

    certs = CertMonitor()
    certs.url = url
    certs.checkFrequency = 3600
    certs.certValid = certInfo.getCertStatus()
    certs.expirationDate = certInfo.certExpirationDate
    certs.save() 
    """
    
    

    certObjs = CertMonitor.objects.all()

    context = {
        "cert_urls": certObjs
    }
    
       
    return render(request, 'polls/sslmonitor.html', context)

def monitorUrl(request):
    website = request.GET.get('website_port')
    if website != "" and (".") in website:
        website_port = get_host_port(website)
        host = website_port[0]
        port = int(website_port[1])
        print(host, port)

    certInfo = polls.views.CertInformation(host,port)
    certs = CertMonitor()
    certs.url = host
    certs.checkFrequency = 3600
    certs.certValid = certInfo.getCertStatus()
    certs.expirationDate = certInfo.certExpirationDate
    certs.save()
    
    
    CertMonitor.objects.filter(pk__in=CertMonitor.objects.filter(type='Active').order_by('-id').values('pk')[:10]).delete()
    certObjs = CertMonitor.objects.all().last()



    #print(list(CertMonitor.objects.values()))
    dictionary = {"hostname":certObjs.certValid,
            "Cert Status":certObjs.certValid,
            "Expiration Date":certObjs.certValid,
            "Check Frequency":certObjs.certValid}

    """  context = {
        "cert_urls": certObjs
    } 
    """
    #certObjs = json.dumps(certObjs)
    print(dictionary)

    #return render(request, 'polls/sslmonitor.html', context)
    return JsonResponse(dictionary,safe = False)

def get_host_port(website):
    website = website
    if ":" in website:
        port = website.split(":")[1]  # Get port number
        website = website.split(":")[0]
    else:
        website = website
        port = 443  # All exepct port number and colon
    return(website, port)


