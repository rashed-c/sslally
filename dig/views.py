from django.shortcuts import render
from django.http.response import HttpResponse
from modules.dns import *

# Create your views here.


def home(request):
    answers = resolver.query('dnspython.org', 'MX')
    for rdata in answers:
        print('Host', rdata.exchange, 'has preference', rdata.preference)
    return render(request, 'polls/dns-result.html', {'dnsinfo':rdata})
