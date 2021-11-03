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
    dig_result={}
    
   
    
    def A():
        dig_result={"A Records":[]}
        try:
            answer_a = resolver.query(website, "A")
            for rdata in answer_a:
                dig_result["A Records"].append({"A": str(rdata)})
        except:
            pass
        return dig_result

    def AAAA():    
        dig_result={"AAAA":[]}    
        try:
            answer_aaaa = resolver.query(website, "AAAA")
            for rdata in answer_aaaa:
                dig_result.append(rdata)
        except:
            pass
        return dig_result

    def MX():
        dig_result={"MX Records":[]}
        try:
            answer_mx = resolver.query(website, "MX")
            for rdata in answer_mx:
                dig_result["MX Records"].append({"MX":str(rdata.exchange),
                                        "Preference": rdata.preference})
        except:
            pass
        return dig_result
    def NS():
        dig_result={"NS Records":[]}
        try:
            answer_NS = resolver.query(website, "NS")
            for rdata in answer_NS:
                dig_result["NS Records"].append({"NS":str(rdata)})
        except:
            pass
        return dig_result


    def TXT():
        dig_result={"TXT Records":[]}
        try:
            answer_TXT = resolver.query(website, "TXT")
            for rdata in answer_TXT:
                dig_result["TXT Records"].append({"TXT":str(rdata)})
        except:
            pass
        return dig_result

    def SOA():
        try:
            dig_result={"SOA Records":[]}
            answer_SOA = resolver.query(website, "SOA")
            for rdata in answer_SOA:
                dig_result["SOA Records"].append({"SOA":str(rdata)})
        except:
            pass
        return dig_result

    def CAA():
        dig_result={"CAA Records":[]}
        try:
            answer_CAA = resolver.query(website, "CAA")
            for rdata in answer_CAA:
                dig_result["CAA Records"].append({"CAA":str(rdata)})
        except:
            pass
        return dig_result
    
    if record_type=="A":
        dig_result=A()
    if record_type=="AAAA":
        dig_result=AAAA()
    if record_type=="MX":
        dig_result = MX()
    if record_type=="NS":
        dig_result=NS()
    if record_type=="TXT":
        dig_result=TXT()
    if record_type=="SOA":
        dig_result=SOA()
    if record_type=="CAA":
        dig_result=CAA()
    if record_type=="CNAME":
        try:
            answer = resolver.query(website, "CNAME")
            for rdata in answer:
                print(rdata)
        except:
            pass
    if record_type=="SRV":
        try:
            answer = resolver.query(website, "SRV")
            for rdata in answer:
                print(rdata)
        except:
            pass
    if record_type=="PTR":
        try:
            answer = resolver.query(website, "PTR")
            for rdata in answer:
                print(rdata)
        except:
            pass
    if record_type=="ANY":
        #Unpacking method used to merge all the dictionries
        dig_result = {**A(),**AAAA(),**MX(),**NS(),**TXT(),**SOA(),**CAA()}


    # try:
    #     dig_result = resolver.query(website,record_type)
    # except:
    #     dig_result = "No record found!"

    
    answers_json = json.dumps(dig_result)

    print(answers_json)
        
        #print('Host', rdata.exchange, 'has preference', rdata.preference)
    return HttpResponse(answers_json)
    #return render(request, 'polls/dig-result.html', {'dnsinfo':dig_result})
