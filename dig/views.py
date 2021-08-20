import dig
from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.dns import *
import json

# Create your views here.


def home(request):
    return render(request, 'polls/dig-home.html', {'dnsinfo':rdata})

def do_dig(request):
    website = request.GET.get('website_port')
    record_type = request.GET.get('record_type')
    print(website)
    print(record_type)
    answers = resolver.query(website, record_type)
    dig_result = []
    for rdata in answers:
        dig_result.append(rdata)
        #print('Host', rdata.exchange, 'has preference', rdata.preference)
    print (HttpResponse(answers))
    return HttpResponse(answers)
    #return render(request, 'polls/dig-result.html', {'dnsinfo':dig_result})
