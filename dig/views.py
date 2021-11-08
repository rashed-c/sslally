import dig
from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.dns import *
import json 
from pprint import pprint

# Create your views here.


def home(request):
    return render(request, 'polls/dig-home.html')

def do_dig(request):
    my_resolver = resolver.Resolver()
    
    website = request.GET.get('website_port')
    record_type = request.GET.get('record_type')
    dns_server = request.GET.get('dns_server')
    dig_result={}
    print(dns_server)
    if(dns_server == "Google"):
        my_resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    elif(dns_server == "OpenDNS"):
        my_resolver.nameservers = ['1.2.3.4']
    elif(dns_server == "Cloudflare"):
        my_resolver.nameservers = ['1.1.1.1']
   
    
    def A():
        dig_result={"A Records":[]}
        try:
            answer_a = my_resolver.query(website, "A")
            for rdata in answer_a:
                dig_result["A Records"].append({"A": str(rdata)})
                print(rdata)
                print(rdata.rrset.ttl)
        except Exception as e:
            print(e)
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
            answer_mx = my_resolver.query(website, "MX")
            for rdata in answer_mx:
                dig_result["MX Records"].append({"MX":str(rdata.exchange),
                                        "Preference": rdata.preference})
                pprint(vars(rdata))
        except:
            pass
        return dig_result

    def NS():
        dig_result={"NS Records":[]}
        try:
            answer_NS = my_resolver.query(website, "NS")
            for rdata in answer_NS:
                dig_result["NS Records"].append({"NS":str(rdata)})
        except:
            pass
        return dig_result


    def TXT():
        dig_result={"TXT Records":[]}
        try:
            answer_TXT = my_resolver.query(website, "TXT")
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
            answer = my_resolver.query(website, "CNAME")
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
