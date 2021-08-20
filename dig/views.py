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
    dig_result = []
    if record_type == "ANY":
        answer_a = resolver.query(website, "A")
        for rdata in answer_a:
            dig_result.append(rdata)
        try:
            answer_aaaa = resolver.query(website, "AAAA")
            for rdata in answer_aaaa:
                dig_result.append(rdata)
        except:
            pass
        answer_mx = resolver.query(website, "MX")
        for rdata in answer_mx:
            dig_result.append(rdata)
        answer_NS = resolver.query(website, "NS")
        for rdata in answer_NS:
            dig_result.append(rdata)
        answer_TXT = resolver.query(website, "TXT")
        for rdata in answer_TXT:
            dig_result.append(rdata)
        answer_SOA = resolver.query(website, "SOA")
        for rdata in answer_SOA:
            dig_result.append(rdata)
        try:
            answer_CAA = resolver.query(website, "CAA")
            for rdata in answer_CAA:
                dig_result.append(rdata)
        except:
            pass
        
        answers= dig_result
    else:
        try:
            answers = resolver.query(website, record_type)
        except:
            answers = "No record found!"

        #print('Host', rdata.exchange, 'has preference', rdata.preference)
    return HttpResponse(answers)
    #return render(request, 'polls/dig-result.html', {'dnsinfo':dig_result})
