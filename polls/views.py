
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




@background(schedule = 0)
def get_cipher_suites(website,port):
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(website, port)
    server_info = ServerConnectivityTester().perform(server_location)
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        #server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,ScanCommand.SSL_3_0_CIPHER_SUITES,ScanCommand.TLS_1_0_CIPHER_SUITES,ScanCommand.TLS_1_1_CIPHER_SUITES,ScanCommand.TLS_1_2_CIPHER_SUITES,ScanCommand.TLS_1_3_CIPHER_SUITES},
        server_info=server_info, scan_commands={ScanCommand.SSL_2_0_CIPHER_SUITES,ScanCommand.SSL_3_0_CIPHER_SUITES,ScanCommand.TLS_1_0_CIPHER_SUITES,ScanCommand.TLS_1_1_CIPHER_SUITES,ScanCommand.TLS_1_2_CIPHER_SUITES,ScanCommand.TLS_1_3_CIPHER_SUITES},)
    scanner.queue_scan(server_scan_req)

    for server_scan_result in scanner.get_results():
        
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")
        # SSL 2.0 results
        ssl2_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
        accepted_ssl20 = []
        print("\nAccepted cipher suites for SSL 2.0:")
        for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
            accepted_ssl20.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # SSL 3.0 results
        ssl3_result = server_scan_result.scan_commands_results[ScanCommand.SSL_3_0_CIPHER_SUITES]
        accepted_ssl30 = []
        print("\nAccepted cipher suites for SSL 3.0:")
        for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
            accepted_ssl30.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}")
            
        # TLS 1.0 results
        tls10_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_0_CIPHER_SUITES]
        accepted_tls10 = []
        print("\nAccepted cipher suites for TLS 1.0:")
        for accepted_cipher_suite in tls10_result.accepted_cipher_suites:
            accepted_tls10.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 
        
        # TLS 1.1 results
        tls11_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_1_CIPHER_SUITES]
        accepted_tls11 = []
        print("\nAccepted cipher suites for TLS 1.1:")
        for accepted_cipher_suite in tls11_result.accepted_cipher_suites:
            accepted_tls11.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 
        
        # TLS 1.2 results
        tls12_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_2_CIPHER_SUITES]
        accepted_tls12 = []
        print("\nAccepted cipher suites for TLS 1.2:")
        for accepted_cipher_suite in tls12_result.accepted_cipher_suites:
            accepted_tls12.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 

        #TLS 1.3 results
        #tls13_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_3_CIPHER_SUITES]
        #print(tls13_result)
        
        accepted_tls13 = []
        print("\nAccepted cipher suites for TLS 1.3:")
        for accepted_cipher_suite in tls12_result.accepted_cipher_suites:
            accepted_tls13.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 
        
        

        '''
        Other available results:
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
       
      
        # Certificate info results
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES,ScanCommand.SSL_3_0_CIPHER_SUITES,ScanCommand.TLS_1_0_CIPHER_SUITES,ScanCommand.TLS_1_1_CIPHER_SUITES,ScanCommand.TLS_1_2_CIPHER_SUITES,ScanCommand.TLS_1_3_CIPHER_SUITES]
        #print(certinfo_result)
        server_scan_result_as_json = json.dumps(asdict(certinfo_result), cls=sslyze.JsonEncoder)
        certinfo_json = json.loads(server_scan_result_as_json)
        print(certinfo_json)
      
        cert_dns_subject_alternative = certinfo_json['certificate_deployments'][0]['received_certificate_chain'][0]['subject_alternative_name']['dns']
        cert_expiration_date = certinfo_json['certificate_deployments'][0]['received_certificate_chain'][0]['not_valid_after']
        certinfo_view = {'sn' : cert_dns_subject_alternative, 
                         'exp' : cert_expiration_date}
                      
        for cert_deployment in certinfo_result.certificate_deployments:
            print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain}")
        '''
    return str(accepted_tls13)


@ratelimit(key='ip')
def home(request):
    return render(request, 'polls/ssl-home.html')

@ratelimit(key='user_or_ip', rate='5/s', method=ratelimit.ALL)
def result(request):
    #data = pd.read_csv('https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsCSV', skipinitialspace=True)
    #print(df.loc["067f94578587e8ac77deb253325bbc998b560d"]["CA Owner"])
    # data = pd.read_csv('https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsCSV', header=0, index_col=7, squeeze=True).to_dict()
    # for key, value in data.items():
    #     print (data[key])
    # for row in df2:
    #     print(row[0]) 
    # # mydict = df.applymap(str).groupby('Certificate Serial Number')['CA Owner'].apply(list).to_dict()
    # # mydict2 = df2.groupby(['Certificate Serial Number']).groups
    # df_test = df2.groupby('Certificate Serial Number')['CA Owner']['Subordinate CA Owner'].apply(list).to_dict()
    # print(df_test)

    #print(data)
    #print(data)
    #print(data['0203bc53596b34c718f5015066'])Certificate Serial Number

    was_limited = getattr(request, 'limited', False)
    print("Rate limited: "+str(was_limited))
    website = request.GET.get('website_port')
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443
    
    # try:
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(website, port)
    # except Exception as e:
    #     print(e)

    # Do connectivity testing to ensure SSLyze is able to connect
    # try:
    #     print("here")
    server_info = ServerConnectivityTester().perform(server_location)
    # except Exception as e:
    #     # Could not connect to the server; abort
    #     print(f"Error connecting to {server_location}: {e}")
    #     return
    # Then queue some scan commands for the server
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        #server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,ScanCommand.SSL_3_0_CIPHER_SUITES,ScanCommand.TLS_1_0_CIPHER_SUITES,ScanCommand.TLS_1_1_CIPHER_SUITES,ScanCommand.TLS_1_2_CIPHER_SUITES,ScanCommand.TLS_1_3_CIPHER_SUITES},
        server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO},
   )
    scanner.queue_scan(server_scan_req)

    # Then retrieve the results
    for server_scan_result in scanner.get_results():
        '''
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")
        # SSL 2.0 results
        ssl2_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
        accepted_ssl20 = []
        print("\nAccepted cipher suites for SSL 2.0:")
        for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
            accepted_ssl20.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # SSL 3.0 results
        ssl3_result = server_scan_result.scan_commands_results[ScanCommand.SSL_3_0_CIPHER_SUITES]
        accepted_ssl30 = []
        print("\nAccepted cipher suites for SSL 3.0:")
        for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
            accepted_ssl30.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}")
            
        # TLS 1.0 results
        tls10_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_0_CIPHER_SUITES]
        accepted_tls10 = []
        print("\nAccepted cipher suites for TLS 1.0:")
        for accepted_cipher_suite in tls10_result.accepted_cipher_suites:
            accepted_tls10.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 
        
        # TLS 1.1 results
        tls11_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_1_CIPHER_SUITES]
        accepted_tls11 = []
        print("\nAccepted cipher suites for TLS 1.1:")
        for accepted_cipher_suite in tls11_result.accepted_cipher_suites:
            accepted_tls11.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 
        
        # TLS 1.2 results
        tls12_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_2_CIPHER_SUITES]
        accepted_tls12 = []
        print("\nAccepted cipher suites for TLS 1.2:")
        for accepted_cipher_suite in tls12_result.accepted_cipher_suites:
            accepted_tls12.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 

        # TLS 1.3 results
        tls13_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_3_CIPHER_SUITES]
        print(tls13_result)
        
        accepted_tls13 = []
        print("\nAccepted cipher suites for TLS 1.3:")
        for accepted_cipher_suite in tls12_result.accepted_cipher_suites:
            accepted_tls13.append(accepted_cipher_suite.cipher_suite.name)
            print(f"* {accepted_cipher_suite.cipher_suite.name}") 
        
        
    
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
        
        # Certificate info results
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
        #print(certinfo_result)
        server_scan_result_as_json = json.dumps(asdict(certinfo_result), cls=sslyze.JsonEncoder)
        certinfo_json = json.loads(server_scan_result_as_json)
        #print(certinfo_json)
        '''
        cert_dns_subject_alternative = certinfo_json['certificate_deployments'][0]['received_certificate_chain'][0]['subject_alternative_name']['dns']
        cert_expiration_date = certinfo_json['certificate_deployments'][0]['received_certificate_chain'][0]['not_valid_after']
        certinfo_view = {'sn' : cert_dns_subject_alternative, 
                         'exp' : cert_expiration_date}
                      
        for cert_deployment in certinfo_result.certificate_deployments:
            print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain}")
        ''' 
        

        # full_cert = certinfo_json["certificate_deployments"]
        # print(full_cert)

       
        cert_serial_number = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][1]["serial_number"]
        serial_number_hex = checkCA(cert_serial_number)
        filtered = fnmatch.filter(df.index.values, '*'+serial_number_hex)

        if(filtered):
            cert_organization = df.loc[filtered[0]]['Certificate Subject Organization']
            ca_status = valid_svg
        else:
            cert_organization = "Unknown"
            ca_status = invalid_svg
        
        # for x in df.index.values:
        #     if serial_number_hex in x: 
        #         print(x)


        # for serial in data['Certificate Serial Number']:
        #     #print(serial_number_hex)
        #     if(serial_number_hex in serial):
        #         print(data['Certificate Issuer Common Name'])
        #         print(serial)

        expiration_date = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][0]["not_valid_after"]
        expiration_date = expiration_date[0:-9]
        dns_name = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][0]["subject_alternative_name"]["dns"]
        key_size = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][0]["public_key"]["key_size"]
        

        if(key_size >= 2048):
            key_status = valid_svg
        else:
            key_status = warning_svg
        

        if (datetime.strptime(expiration_date,'%Y-%m-%d') - datetime.today()).days > 30: 
            expiration_status = valid_svg
        elif (datetime.strptime(expiration_date,'%Y-%m-%d') - datetime.today()).days > 0: 
            expiration_status = warning_svg
        else: 
            expiration_status = invalid_svg


        
        expiration_date = (datetime.strptime(expiration_date,'%Y-%m-%d').strftime('%B %d, %Y'))


        host_name = "" 
        filtered = fnmatch.filter(dns_name,website)
        if filtered:
            host_status = valid_svg
            for name in dns_name:
                if name == website:
                    host_name += '<div class="bg-gray-300 font-bold">'+name+"</div>"
                else:
                    host_name += name+"<br>"
        else:
            website = (get_fld(website, fix_protocol=True))
            filtered = fnmatch.filter(dns_name,"*."+website)
            if(filtered):
                website_highlight = "*."+website
                for name in dns_name:
                    if name == website_highlight:
                       host_name += '<div class="bg-gray-300 font-bold">'+name+"</div>"
                    else:
                        host_name += name+"<br>"
                host_status = valid_svg
            else:
                host_status = invalid_svg


         
        dns_data = {
        '<div class="cursor-pointer pr-2 font-semibold"> Expiration: </div>':'<div class="fontawesome">'+expiration_date+"</div><div class=''>"+expiration_status+"</div>",
        '<div class="cursor-pointer pr-2 font-semibold"> Host name: </div>':'<div class="cursor-pointer fontawesome">'+host_name+"</div>"+"<div class=''>"+host_status+"</div>",
        '<div class="cursor-pointer pr-2 font-semibold"> Certificate Authority: </div>':'<div class="fontawesome">'+cert_organization+"</div>"+"<div class=''>"+ca_status+"</div>",
        '<div class="cursor-pointer pr-2 font-semibold"> Key Size: </div>':'<div class="fontawesome">'+str(key_size)+"</div>"+"<div class=''>"+key_status+"</div>"}

        custom_json = json.dumps(dns_data)
        #full_cert = json.dumps(full_cert)
        #custom_json += get_cipher_suites.now(website,port)
    return JsonResponse(custom_json, safe=False)
    #return render(request, 'polls/result.html', {'certinfo':certinfo_view,'tlsinfo10':accepted_tls10,'tlsinfo11':accepted_tls11,'tlsinfo12':accepted_tls12,'tlsinfo13':accepted_tls13} )

def checkIP(Ip): 
    # pass the regular expression
    # and the string in search() method
    if(re.search(regex, Ip)): 
        print("Valid Ip address") 
    else: 
        print("Invalid Ip address") 


def checkCA(cert_serial):
    cert_serial_hex = hex(cert_serial)
    #cert_serial_hex = ("0"+cert_serial_hex[2:]).upper()
    cert_serial_hex = (cert_serial_hex[2:]).upper()
    return cert_serial_hex
    


