
from django.http.response import HttpResponse, JsonResponse
from django.shortcuts import render
from modules.sslyze import *
import sslyze
from dataclasses import asdict
import json
import re
from datetime import datetime
from ratelimit.decorators import ratelimit
# Make a regular expression
# for validating an Ip-address
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
 


@ratelimit(key='ip')
def home(request):
    return render(request, 'polls/ssl-home.html')

@ratelimit(key='ip', rate='1/h')
def result(request):
    website = request.GET.get('website_port')
    if ":" in website:
        port = website[-3:] # Get port number
        website = website[0:-4] # All exepct port number and colon
    else:
        port=443

    
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(website, port)

    # Do connectivity testing to ensure SSLyze is able to connect
    try:
        server_info = ServerConnectivityTester().perform(server_location)
    except ConnectionToServerFailed as e:
        # Could not connect to the server; abort
        print(f"Error connecting to {server_location}: {e.error_message}")
        return
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

        expiration_date = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][0]["not_valid_after"]
        expiration_date = expiration_date[0:-9]
        
        valid_svg='<svg xmlns="http://www.w3.org/2000/svg" class="h-7 w-7 fill-current text-green-600" viewBox="0 0 20 20" fill="currentColor"> <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>'
        expiring_svg ='<svg xmlns="http://www.w3.org/2000/svg" class="h-7 w-7 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
        invalid_svg ='<svg xmlns="http://www.w3.org/2000/svg" class="h-7 w-7 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
       
        dns_name = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][0]["subject_alternative_name"]["dns"]

        public_key_size = certinfo_json["certificate_deployments"][0]["received_certificate_chain"][0]["public_key"]["key_size"]
        print(public_key_size)

        if (datetime.strptime(expiration_date,'%Y-%m-%d') - datetime.today()).days > 30: 
            expiration_status = valid_svg
        elif (datetime.strptime(expiration_date,'%Y-%m-%d') - datetime.today()).days > 0: 
            expiration_status = expiring_svg
        else: 
            expiration_status = invalid_svg

        host_name = ""
        
        for name in dns_name:
            host_name += name+"<br>"

        if website in host_name:
            host_status = valid_svg
        else:
            host_status = invalid_svg
         
        dns_data = {
        "<div> Expiration: </div>":"<div>"+expiration_date+"</div><div>"+expiration_status+"</div>",
        "<div> Host name: </div>":"<div>"+host_name+"</div>"+"<div>"+host_status+"</div>",
        "Certificate Authority: ": serial_number_hex}
        
        custom_json = json.dumps(dns_data)
        #full_cert = json.dumps(full_cert)
        
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
    return cert_serial_hex
    


