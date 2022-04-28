import dig
from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.dns import *
import json
from pprint import pprint
my_resolver = resolver.Resolver()


def home(request):
    return render(request, 'polls/dig.html')


def do_dig(request):
    website = request.GET.get('website_port')
    record_type = request.GET.get('record_type')
    dns_server = request.GET.get('dns_server')
    dig_result = {}
    if(dns_server == "Google"):
        my_resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    elif(dns_server == "OpenDNS"):
        my_resolver.nameservers = ['208.67.222.22', '208.67.220.220']
    elif(dns_server == "Cloudflare"):
        my_resolver.nameservers = ["1.1.1.1"]

    def resolve_query(query_type):

        dig_result = {query_type: []}
        try:
            answer = my_resolver.query(website, query_type)
            for rdata in answer:
                ttl = answer.rrset.ttl
                result = rdata
                dig_result[query_type].append(
                    {query_type: str(result), "TTL": str(ttl)})
        except Exception as e:
            dig_result[query_type].append(
                {query_type: f"No {query_type} records found!"})

        return dig_result

    dig_result = resolve_query(record_type)

    # Unpacking method used to merge all the dictionries
    if record_type == "ANY":
        dig_result = {**resolve_query("A"), **resolve_query("AAAA"),
                      **resolve_query("ANY"), **resolve_query("CAA"),
                      **resolve_query("CNAME"), **resolve_query("MX"),
                      **resolve_query("NS"), **resolve_query("PTR"),
                      **resolve_query("SOA"), **resolve_query("SRV"),
                      **resolve_query("TXT")}
    try:
        answers = json.dumps(dig_result)
    except:
        pass

    return HttpResponse(answers)
