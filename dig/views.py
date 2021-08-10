from django.shortcuts import render
from django.http.response import HttpResponse
import modules.pydig

# Create your views here.


def home(request):
    a_record = pydig.query('google.com', 'A')
    return HttpResponse(a_record)
