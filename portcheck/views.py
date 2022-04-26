from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.icmplib import *
from ratelimit.decorators import ratelimit
import socket
from contextlib import closing

# Create your views here.


@ratelimit(key='ip', rate='1/m')
def home(request):
    return render(request, 'polls/portcheck.html')


def get_host_port(website):
    website = website
    if ":" in website:
        port = website.split(":")[1]  # Get port number
        website = website.split(":")[0]
    else:
        website = website
        port = 443  # All exepct port number and colon
    return(website, port)


# def check_port():
#     print(get_port_status("nessadc.com", 443))


def get_port_status(request):
    website = request.GET.get('website_port')
    if website != "" and (".") in website:
        websiet_port = get_host_port(website)
        host = websiet_port[0]
        port = int(websiet_port[1])
        print(host, port)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(2)
            if sock.connect_ex((host, port)) == 0:
                result = f"Port {port} is open"
            else:
                result = f"Port {port} is closed"
        return JsonResponse(result, safe=False)
    else:
        print("website is empty")
        return JsonResponse("Enter proper value", safe=False)
