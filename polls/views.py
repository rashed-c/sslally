
from os import path, read
import re
from typing import Match
from django.http.response import HttpResponse, JsonResponse
from django.shortcuts import render
from modules.sslyze import *
import sslyze
from dataclasses import asdict
import json
from tld import get_tld, get_fld
import re
import requests
from datetime import datetime
from ratelimit.decorators import ratelimit
import pandas as pd
import fnmatch
from background_task import background
# Make a regular expression
# for validating an Ip-address
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
df = pd.read_csv('https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsCSV', header=0, index_col='Certificate Serial Number') 
valid_svg='<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 fill-current text-green-600" viewBox="0 0 20 20" fill="currentColor"> <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>'
warning_svg ='<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-yellow-400" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>'
invalid_svg ='<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-red-500" viewBox="0 0 20 20" fill="currentColor"> <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
supported_suites = {'ssl2.0':[],'ssl3.0':[],'tls1.0':[],'tls1.1':[], 'tls1.2':[], 'tls1.3':[]}

#@background(schedule = 0)
def get_ssl_2_0(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    accepted_ciphers = getProtocol(website,port,"ssl2.0")
    accepted_ciphers = {'<div class="cursor-pointer pr-2 font-semibold"> SSL 2.0 Ciphers: </div>':'<div class="fontawesome">'+str(accepted_ciphers)+"</div><div class=''>"+valid_svg+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_ssl_3_0(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    accepted_ciphers = getProtocol(website,port,"ssl3.0")
    accepted_ciphers = {'<div class="cursor-pointer pr-2 font-semibold"> SSL 3.0 Ciphers: </div>':'<div class="fontawesome">'+str(accepted_ciphers)+"</div><div class=''>"+valid_svg+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_tls_1_0(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    accepted_ciphers = getProtocol(website,port,"tls1.0")
    accepted_ciphers = {'<div class="cursor-pointer pr-2 font-semibold"> TLS 1.0 Ciphers: </div>':'<div class="fontawesome">'+str(accepted_ciphers)+"</div><div class=''>"+valid_svg+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_tls_1_1(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    accepted_ciphers = getProtocol(website,port,"tls1.1")
    accepted_ciphers = {'<div class="cursor-pointer pr-2 font-semibold"> TLS 1.1 Ciphers: </div>':'<div class="fontawesome">'+str(accepted_ciphers)+"</div><div class=''>"+valid_svg+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_tls_1_2(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    accepted_ciphers = getProtocol(website,port,"tls1.2")
    accepted_ciphers = {'<div class="cursor-pointer pr-2 font-semibold"> TLS 1.2 Ciphers: </div>':'<div class="fontawesome">'+str(accepted_ciphers)+"</div><div class=''>"+valid_svg+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_tls_1_3(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    accepted_ciphers = getProtocol(website,port,"tls1.3")
    accepted_ciphers = {'<div class="cursor-pointer pr-2 font-semibold"> TLS 1.3 Ciphers: </div>':'<div class="fontawesome">'+str(accepted_ciphers)+"</div><div class=''>"+valid_svg+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

@ratelimit(key='ip')
def home(request):
    return render(request, 'polls/ssl-home.html')

def test_ssl_cert(request):
    website = request.GET.get('website_port')
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    cert = getCert(website,port)



@ratelimit(key='user_or_ip', rate='1/5s', method=ratelimit.ALL)
def result(request):
    #Rate limit test
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        print("please wait 10 seconds")
    print("Rate limited: "+str(was_limited))

    website = request.GET.get('website_port')
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
         
    '''
    Transform to uppercase first:
    SSL_2_0_CIPHER_SUITES: CipherSuitesScanResult
    SSL_3_0_CIPHER_SUITES: CipherSuitesScanResult
    tls_1_0_cipher_suites: CipherSuitesScanResult
    tls_1_1_cipher_suites: CipherSuitesScanResult
    tls_1_2_cipher_suites: CipherSuitesScanResult
    tls_1_3_cipher_suites: CipherSuitesScanResult
    tls_compression: CompressionScanResult
    tls_1_3_early_data: EarlyDataScanResult
    openssl_ccs_injection: OpenSslCcsInjectionScanResult
    tls_fallback_scsv: FallbackScsvScanResult
    heartbleed: HeartbleedScanResult
    robot: RobotScanResult
    session_renegotiation: SessionRenegotiationScanResult
    session_resumption: SessionResumptionSupportScanResult
    session_resumption_rate: SessionResumptionRateScanResult
    http_headers: HttpHeadersScanResult
    elliptic_curves: SupportedEllipticCurvesScanResult
    '''

    certs= getCert(website,port)
    # print(certs)
    # cert_data=[{"Main Certs":[],"Other Certs":[], "Cert Path":[]}]
    # cert_data={"Main Certs":[],"Other Certs":[],"Cert Path":[]}
    # for dep_num in range(len(certs["cert_deployments"])):
    #     cert_data["Main Certs"].append([])
    #     cert_data["Other Certs"].append([])
    #     cert_data["Cert Path"].append([])
    #     for cert_num in range(len(certs["cert_deployments"][dep_num]["received_certificate_chain"])):
    #         if cert_num == 0:
    #             cert_data["Main Certs"][dep_num].append(certs["cert_deployments"][dep_num]["received_certificate_chain"][cert_num])
    #         else:
    #             cert_data["Other Certs"][dep_num].append(certs["cert_deployments"][dep_num]["received_certificate_chain"][cert_num])
    #     for path_num in range(len(certs["cert_deployments"][dep_num]["path_validation_results"])):
    #         cert_data["Cert Path"][dep_num].append([])
    #         cert_data["Cert Path"][dep_num][path_num].append({certs["cert_deployments"][dep_num]["path_validation_results"][path_num]["chain_name"]:[]})
    #         #print(cert_data["Cert Path"][dep_num][path_num])
    #         for path_cert_num in range(len(certs["cert_deployments"][0]["path_validation_results"][path_num]["verrified_certificate_chain"])):
    #             #print(certs["cert_deployments"][0]["path_validation_results"][path_num]["verrified_certificate_chain"])
    #             cert_data["Cert Path"][dep_num][path_num].append(certs["cert_deployments"][dep_num]["path_validation_results"][path_num]["verrified_certificate_chain"][path_cert_num])



    # #cert_data[0]["Main Cert"].append(certs["cert_deployments"][dep_num]["received_certificate_chain"][cert_num])
    # # cert_data={"Main Certs":[],"Other Certs":[], "Cert Path":[]}
    
    # # for dep_num in range(len(certs["cert_deployments"])):
    # #     for cert_num in range(len(certs["cert_deployments"][dep_num]["received_certificate_chain"])):
    # #         if cert_num == 0:
    # #             cert_data["Main Certs"].append(certs["cert_deployments"][dep_num]["received_certificate_chain"][cert_num])
    # #         else:
    # #             cert_data["Other Certs"].append(certs["cert_deployments"][dep_num]["received_certificate_chain"][cert_num])
    # #     for path_num in range(len(certs["cert_deployments"][dep_num]["path_validation_results"])):
    # #         path_name = certs["cert_deployments"][dep_num]["path_validation_results"][path_num]["chain_name"]
    # #         cert_data["Cert Path"].append({"Name":path_name, "Path Chain":[]})
    # #         for path_chain_num in range(len(certs["cert_deployments"][dep_num]["path_validation_results"][path_num]["verrified_certificate_chain"])):
    # #             cert_data["Cert Path"][path_num]["Path Chain"].append(certs["cert_deployments"][dep_num]["path_validation_results"][path_num]["verrified_certificate_chain"][path_chain_num])
        
    #     # for cert_num in range(len(certs["cert_deployments"][dep_num]["received_certificate_chain"])):
    #     #     if cert_num == 0:
    #     #         cert_data["Main Certs"].append(certs["cert_deployments"][0]["received_certificate_chain"][cert_num])
    #     #     else:
    #     #         cert_data["Other Certs"].append(certs["cert_deployments"][0]["received_certificate_chain"][cert_num])
    #     # for path_num in range(len(certs["cert_deployments"][0]["path_validation_results"])):
    #     #     path_name = certs["cert_deployments"][0]["path_validation_results"][path_num]["chain_name"]
    #     #     cert_data["Cert Path"].append({"Name":path_name, "Path Chain":[]})
    #     #     for path_chain_num in range(len(certs["cert_deployments"][0]["path_validation_results"][path_num]["verrified_certificate_chain"])):
    #     #         cert_data["Cert Path"][path_num]["Path Chain"].append(certs["cert_deployments"][0]["path_validation_results"][path_num]["verrified_certificate_chain"][path_chain_num])
        
    # print(cert_data)



        


    # cert_data=[]
    # deployment_num = 0
    # for deployment in cert_deployments:
    #     for cert in deployment:
    #         cert_num = 0
    #         #Main cert
    #         if (cert == cert_deployments[deployment_num][0]):
    #             cert_data.append([{"Main cert" : 
    #             {"Certificate #: " : cert[0]["Certificate #"],
    #             "Valid from: " : cert[0]["Valid from"],
    #             "Host name: " : cert[0]["DNS Name"],
    #             "Expiration date: " : cert[0]["Expiration Date"]}}])

    #         #Intermediate cert
    #         else: 
    #             cert_data[0].append([{"Valid from" : cert[cert_num]["Valid from"],
    #             "Serial Number" : cert[cert_num]["Serial Number"],
    #           #  "Host name" : cert[cert_num]["DNS Name"],
    #             "Expiration Date" : cert[cert_num]["Expiration Date"]}])
    #         #     "Host name" : cert_deployments[deployment][cert]["DNS Name"],
    #         #     "Expiration date" : cert_deployments[deployment][cert]["Expiration Date"]}])
    #     deployment_num +=1
    # cert_data = {'<div class="cursor-pointer pr-2 font-semibold"> Valid between: </div>':'<div class="fontawesome">'+validfrom_date+" - "+expiration_date+"</div>",
    # '<div class="cursor-pointer pr-2 font-semibold"> Host name: </div>':'<div class="cursor-pointer fontawesome">'+str(host_names)+"</div>"+"<div class=''>"+valid_svg+"</div>",}
    # #'<div class="cursor-pointer pr-2 font-semibold"> Certificate Authority: </div>':'<div class="fontawesome">'+cert_organization+"</div>"+"<div class=''>"+ca_status+"</div>"}
    #print(cert_data)

    cert_data_json = json.dumps(certs)
    return JsonResponse(cert_data_json, safe=False)
    #return render(request, 'polls/result.html', {'certinfo':certinfo_view,'tlsinfo10':accepted_tls10,'tlsinfo11':accepted_tls11,'tlsinfo12':accepted_tls12,'tlsinfo13':accepted_tls13} )

def getCert(website,port):
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(website, port)
    server_info = ServerConnectivityTester().perform(server_location)
    scanner = Scanner()
    server_scan_req = ServerScanRequest(server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO}, )
    scanner.queue_scan(server_scan_req)
    cert = {"cert_deployments":[]}
    for server_scan_result in scanner.get_results():
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
        server_scan_result_as_json = json.dumps(asdict(certinfo_result), cls=sslyze.JsonEncoder)
        certinfo_json = json.loads(server_scan_result_as_json)
        #print(certinfo_json)
        for dep_num in range(len(certinfo_json['certificate_deployments'])):
            cert["cert_deployments"].append({"received_certificate_chain":[],"path_validation_results":{}})
            for cert_num in range(len(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"])):
                serial = checkCA(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["serial_number"])
                cert_authority = getCertificateAuthority(serial)
                validfrom_date = formatDate(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["not_valid_before"])
                notvalidafter_date = formatDate(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["not_valid_after"])
                hpkp_pin = certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["hpkp_pin"]
                key_size = certinfo_json["certificate_deployments"][dep_num]["received_certificate_chain"][cert_num]["public_key"]["key_size"]

                cert["cert_deployments"][dep_num]["received_certificate_chain"].append({"<div>Serial number: </div>": serial, "<div>Valid from: </div>": validfrom_date, "<div>Not valid after: </div>":notvalidafter_date ,"<div>cert_authority: </div>":cert_authority, "<div>hpkp_pin: </div>":hpkp_pin, "<div>key_size: </div>":key_size})
                #cert["cert_deployments"][dep_num]["received_certificate_chain"][cert_num]["serial_number"] = serial_int   
                #cert["cert_deployments"][dep_num].append({"received_certificate_chain":[cert_num]})

            for path_num in range(len(certinfo_json['certificate_deployments'][dep_num]["path_validation_results"])):
                chain_name = certinfo_json['certificate_deployments'][dep_num]["path_validation_results"][path_num]["trust_store"]["name"]
                #cert["cert_deployments"][dep_num]["path_validation_results"].append({"chain_name":chain_name,"verrified_certificate_chain":[]})
                cert["cert_deployments"][dep_num]["path_validation_results"][chain_name] = []
                for path_chain_num in range(len(certinfo_json['certificate_deployments'][dep_num]["path_validation_results"][path_num]["verified_certificate_chain"])):
                    serial = checkCA(certinfo_json['certificate_deployments'][dep_num]["path_validation_results"][path_num]["verified_certificate_chain"][path_chain_num]["serial_number"])
                    cert_authority = getCertificateAuthority(serial)
                    cert["cert_deployments"][dep_num]["path_validation_results"][chain_name].append({"<div>Serial number: </div>":serial, "<div>cert_authority: </div>":cert_authority})
                
                    #.append([{"serial_number": serial}])


        # deployment_num = 0     
        # for deployment in (certinfo_json["certificate_deployments"]):
        #     cert.append([])
        #     chain_num = 0
        #     for cert_chain in (certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"]):
        #         certificate_num = deployment_num+1
        #         hpkp_pin = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["hpkp_pin"]
        #         cert_serial_number = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["serial_number"]
        #         expiration_date = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["not_valid_after"]
        #         expiration_date = expiration_date[0:-9]
        #         expiration_date = (datetime.strptime(expiration_date,'%Y-%m-%d').strftime('%B %d, %Y'))
        #         validfrom_date = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["not_valid_before"]
        #         validfrom_date = validfrom_date[0:-9]
        #         validfrom_date = (datetime.strptime(validfrom_date,'%Y-%m-%d').strftime('%B %d, %Y'))
        #         dns_name = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["subject_alternative_name"]["dns"]
        #         host_name = [] 
        #         filtered = fnmatch.filter(dns_name,website)
        #         if filtered:
        #             host_status = valid_svg
        #             for name in dns_name:
        #                 if name == website:
        #                     host_name.append('<div class="bg-gray-300 font-bold">'+name+"</div>")
        #                 else:
        #                     host_name.append(name+", ")
        #         else:
        #             website = (get_fld(website, fix_protocol=True))
        #             filtered = fnmatch.filter(dns_name,"*."+website)
        #             if(filtered):
        #                 website_highlight = "*."+website
        #                 for name in dns_name:
        #                     if name == website_highlight:
        #                         host_name.append('<div class="bg-gray-300 font-bold">'+name+"</div>")
        #                     else:
        #                         host_name.append(name+"<br>")
        #                 host_status = valid_svg
        #             else:
        #                 host_status = invalid_svg
        #         host_names = ""
        #         for name in host_name:
        #             host_names += name
        #         key_size = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["public_key"]["key_size"]
        #         cert_serial_number = certinfo_json["certificate_deployments"][deployment_num]["received_certificate_chain"][chain_num]["serial_number"]
        #         serial_number_hex = checkCA(cert_serial_number)
        #         cert[deployment_num].append([])
        #         cert[deployment_num][chain_num].append({"Certificate #": certificate_num,"Serial Number" : serial_number_hex, "hpkp_pin": hpkp_pin, "Expiration Date": expiration_date, "Valid from": validfrom_date,"DNS Name": host_name, "Key size": key_size})
        #         #cert.append({deployment_num:{chain_num:{"Serial Number" : serial_number_hex, "hpkp_pin": hpkp_pin, "Expiration Date": expiration_date, "Valid from": validfrom_date,"DNS Name": dns_name, "Key size": key_size}}})
        #         path_num=0
        #         for path in (certinfo_json["certificate_deployments"][deployment_num]["path_validation_results"]):
        #             print(certinfo_json["certificate_deployments"][deployment_num]["path_validation_results"][path_num]["trust_store"]["name"])
        #             path_num += 1
        #         chain_num +=1
        #     deployment_num +=1
    return (cert)
    

def formatDate(date):
    date = date[0:-9]
    date = (datetime.strptime(date,'%Y-%m-%d').strftime('%B %d, %Y'))
    return date



def getProtocol(website,port,protocol):
    supported_suites = {protocol:[]}
    if(protocol == "ssl2.0"):
        command = ScanCommand.SSL_2_0_CIPHER_SUITES
    elif(protocol == "ssl3.0"):
        command = ScanCommand.SSL_3_0_CIPHER_SUITES
    elif(protocol == "tls1.0"):
        command = ScanCommand.TLS_1_0_CIPHER_SUITES
    elif(protocol == "tls1.1"):
        command = ScanCommand.TLS_1_1_CIPHER_SUITES
    elif(protocol == "tls1.2"):
        command = ScanCommand.TLS_1_2_CIPHER_SUITES
    elif(protocol == "tls1.3"):
        command = ScanCommand.TLS_1_3_CIPHER_SUITES
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(website, port)
    server_info = ServerConnectivityTester().perform(server_location)
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        #server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,ScanCommand.SSL_3_0_CIPHER_SUITES,ScanCommand.TLS_1_0_CIPHER_SUITES,ScanCommand.TLS_1_1_CIPHER_SUITES,ScanCommand.TLS_1_2_CIPHER_SUITES,ScanCommand.TLS_1_3_CIPHER_SUITES},
        server_info=server_info, scan_commands={command},)
    scanner.queue_scan(server_scan_req)

    for server_scan_result in scanner.get_results():
        cipher_result = server_scan_result.scan_commands_results[command]
        accepted_ciphers = ""
        for accepted_cipher_suite in cipher_result.accepted_cipher_suites:
            accepted_ciphers += (accepted_cipher_suite.cipher_suite.name+", ")
            supported_suites[protocol].append(accepted_cipher_suite.cipher_suite.name)
        if(accepted_ciphers):
            pass
        else:
            accepted_ciphers = protocol + " not supported"
        #accepted_ciphers = json.dumps(accepted_ciphers)
        print(supported_suites)
        return (supported_suites[protocol])
        
def checkIP(Ip): 
    # pass the regular expression
    # and the string in search() method
    if(re.search(regex, Ip)): 
        print("Valid Ip address") 
    else: 
        print("Invalid Ip address") 

def checkCA(cert_serial):
    cert_serial_hex = hex(cert_serial)
    cert_serial_hex = (cert_serial_hex[2:]).upper()
    return cert_serial_hex

def getCertificateAuthority(serial_number_hex):
    filtered = fnmatch.filter(df.index.values, '*'+serial_number_hex)
    if(filtered):
        cert_organization = df.loc[filtered[0]]['Certificate Subject Organization']
        ca_status = valid_svg
    else:
        cert_organization = "Unknown"
        ca_status = invalid_svg
    return(cert_organization)


    


