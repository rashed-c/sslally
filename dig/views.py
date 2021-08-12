from django.shortcuts import render
from django.http.response import HttpResponse
from modules.dns import *

# Create your views here.


def home(request):
    return render(request, 'polls/dig-home.html', {'dnsinfo':rdata})

def do_dig(request):
    website = request.GET.get('website_port')
    answers = resolver.query(website, 'MX')
    for rdata in answers:
        print('Host', rdata.exchange, 'has preference', rdata.preference)
    return render(request, 'polls/dig-result.html', {'dnsinfo':rdata})
