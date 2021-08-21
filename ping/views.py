from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.icmplib import *

# Create your views here.


def home(request):
    return render(request, 'polls/ping-home.html')

def do_ping(request):
    website = request.GET.get('website_port')
    ping_result = []
    host = ping(website, count=5, interval=1, privileged=True)
    print(host)
    #return JsonResponse()
    return HttpResponse(host)
    #return render(request, 'polls/ping-result.html', {'pinginfo':host})