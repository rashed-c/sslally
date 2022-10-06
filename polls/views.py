
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
from dateutil import parser
# Make a regular expression
# for validating an Ip-address
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
df = pd.read_csv('https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsCSV',
                 header=0, index_col='Certificate Serial Number')
valid_svg = '<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 fill-current text-green-600" viewBox="0 0 20 20" fill="currentColor"> <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>'
warning_svg = '<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-yellow-400" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>'
invalid_svg = '<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-red-500" viewBox="0 0 20 20" fill="currentColor"> <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
supported_suites = {'ssl2.0': [], 'ssl3.0': [],
                    'tls1.0': [], 'tls1.1': [], 'tls1.2': [], 'tls1.3': []}

# @background(schedule = 0)


def get_ssl_2_0(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "ssl2.0")
    accepted_ciphers = {'<div class="cursor-pointer pr-2">SSL 2.0</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)


def get_ssl_3_0(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "ssl3.0")
    accepted_ciphers = {'<div class="cursor-pointer pr-2">SSL 3.0</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)


def get_tls_1_0(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "tls1.0")
    accepted_ciphers = {'<div class="cursor-pointer pr-2"> TLS 1.0</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)

    return JsonResponse(accepted_ciphers, safe=False)


def get_tls_1_1(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "tls1.1")
    accepted_ciphers = {'<div class="cursor-pointer pr-2">TLS 1.1</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_tls_1_1(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "tls1.1")
    accepted_ciphers = {'<div class="cursor-pointer pr-2">TLS 1.1</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)



def get_tls_1_2(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "tls1.2")
    accepted_ciphers = {'<div class="cursor-pointer pr-2">TLS 1.2</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)

def get_tls_1_3(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    accepted_ciphers = getProtocol(website, port, "tls1.3")
    accepted_ciphers = {'<div class="cursor-pointer pr-2">TLS 1.3</div>':
                        '<div class="fontawesome">'+str(accepted_ciphers)+"</div>"}
    accepted_ciphers = json.dumps(accepted_ciphers)
    return JsonResponse(accepted_ciphers, safe=False)



def tls_compression(request):
    website = request.GET.get('website_port')
    print(website)
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443
    cipher_results = getProtocol(website, port, "tls_compression")
    cipher_results = {'<div class="cursor-pointer pr-2">TLS Compression</div>':
                        '<div class="fontawesome">'+str(cipher_results)+"</div>"}
    print(cipher_results)
    cipher_results = json.dumps(cipher_results)
    print(cipher_results)
    return JsonResponse(cipher_results, safe=False)




@ratelimit(key='ip')
def home(request):
    '''
    getProtocol("opac.bu.umk.pl", 443, "tls_compression")
    print (getProtocol("opac.bu.umk.pl", 443, "tls_1_3_early_data"))
    print(getProtocol("opac.bu.umk.pl", 443, "openssl_ccs_injection"))
    print(getProtocol("opac.bu.umk.pl", 443, "tls_fallback_scsv"))
    print(getProtocol("opac.bu.umk.pl", 443, "heartbleed"))
    print(getProtocol("opac.bu.umk.pl", 443, "robot"))
    print(getProtocol("opac.bu.umk.pl", 443, "session_renegotiation"))
    print(getProtocol("opac.bu.umk.pl", 443, "session_resumption"))
    print(getProtocol("opac.bu.umk.pl", 443, "session_resumption_rate"))
    print(getProtocol("opac.bu.umk.pl", 443, "http_headers"))
    print(getProtocol("opac.bu.umk.pl", 443, "elliptic_curves"))
    '''
    return render(request, 'polls/ssl.html')


""" def test_ssl_cert(request):
    website = request.GET.get('website_port')
    if ":" in website:
        port = website.split(":")[1]  # Get port number
        website = website.split(":")[0]  # All exepct port number and colon
    else:
        port = 443
    cert = getCert(website, port) """


@ratelimit(key='user_or_ip', rate='1/5s', method=ratelimit.ALL)
def result(request):
    # Rate limit test
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        print("please wait 10 seconds")
    print("Rate limited: "+str(was_limited))

    website = request.GET.get('website_port')
    if ":" in website:
        port = website[-3:]  # Get port number
        website = website[0:-4]  # All exepct port number and colon
    else:
        port = 443

   

    certs = getCert(website, port)
    cert_data_json = json.dumps(certs)
    return JsonResponse(cert_data_json, safe=False)
    # return render(request, 'polls/result.html', {'certinfo':certinfo_view,'tlsinfo10':accepted_tls10,'tlsinfo11':accepted_tls11,'tlsinfo12':accepted_tls12,'tlsinfo13':accepted_tls13} )


def getCert(website, port):
    cert = {"cert_deployments": []}
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(website, port)
    print(server_location)
    try:
        server_info = ServerConnectivityTester().perform(server_location)
    except:
        return cert
    scanner = Scanner()
    server_scan_req = ServerScanRequest(server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO}, )
    scanner.queue_scan(server_scan_req)
    
    for server_scan_result in scanner.get_results():
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
        server_scan_result_as_json = json.dumps(
            asdict(certinfo_result), cls=sslyze.JsonEncoder)
        certinfo_json = json.loads(server_scan_result_as_json)
        # print(certinfo_json)
        for dep_num in range(len(certinfo_json['certificate_deployments'])):
            cert["cert_deployments"].append(
                {"received_certificate_chain": [], "path_validation_results": {}})
            for cert_num in range(len(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"])):
                as_pem = certinfo_json["certificate_deployments"][dep_num]["received_certificate_chain"][cert_num]["as_pem"]
                subject = certinfo_json["certificate_deployments"][dep_num][
                    "received_certificate_chain"][cert_num]["subject"]["rfc4514_string"]
                serial = getSerialHex(
                    certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["serial_number"])

                # Subject alternative manipulations
                subject_alternative = certinfo_json["certificate_deployments"][dep_num][
                    "received_certificate_chain"][cert_num]["subject_alternative_name"]["dns"]
                subject_alternative = str(subject_alternative)
                subject_alternative = subject_alternative.replace("'", "")
                subject_alternative = subject_alternative[1:-1]

                if(cert_num == 0):
                    serial = getSerialHex(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num+1]["serial_number"])
                    cert_authority = getCertificateAuthority(serial)
                else:
                    cert_authority = getCertificateAuthority(serial)

                validfrom_date = formatDate(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["not_valid_before"])
                notvalidafter_date = getExpirationDays(certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["not_valid_after"])
                expirationDate = certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["not_valid_after"]
                hpkp_pin = certinfo_json['certificate_deployments'][dep_num]["received_certificate_chain"][cert_num]["hpkp_pin"]
                key_size = str(certinfo_json["certificate_deployments"][dep_num]["received_certificate_chain"][cert_num]["public_key"]["key_size"]) + " Bits"
                signature_algorithm = certinfo_json["certificate_deployments"][dep_num]["received_certificate_chain"][cert_num]["signature_algorithm_oid"]["name"]
                cert["cert_deployments"][dep_num]["received_certificate_chain"].append({"pem": as_pem, "<div>Subject: </div>": subject, "<div>Subject Alternatives: </div>": subject_alternative, "<div>Serial number: </div>": serial, "<div>Valid from: </div>": validfrom_date,
                                                                                       "<div>Not valid after: </div>": notvalidafter_date, "expiration_date":expirationDate, "<div>Issuer: </div>": cert_authority, "<div>HPKP Pin: </div>": hpkp_pin, "<div>Signature Algorithm: </div>": signature_algorithm, "<div>Key size: </div>": key_size})

            for path_num in range(len(certinfo_json['certificate_deployments'][dep_num]["path_validation_results"])):
                chain_name = certinfo_json['certificate_deployments'][dep_num]["path_validation_results"][path_num]["trust_store"]["name"]
                cert["cert_deployments"][dep_num]["path_validation_results"][chain_name] = []
                for path_chain_num in range(len(certinfo_json['certificate_deployments'][dep_num]["path_validation_results"][path_num]["verified_certificate_chain"])):
                    as_pem = certinfo_json["certificate_deployments"][dep_num]["path_validation_results"][
                        path_num]["verified_certificate_chain"][path_chain_num]["as_pem"]
                    subject = certinfo_json["certificate_deployments"][dep_num]["path_validation_results"][
                        path_num]["verified_certificate_chain"][path_chain_num]["subject"]["rfc4514_string"]
                    serial = getSerialHex(certinfo_json['certificate_deployments'][dep_num]["path_validation_results"]
                                          [path_num]["verified_certificate_chain"][path_chain_num]["serial_number"])
                    cert_authority = getCertificateAuthority(serial)
                    cert["cert_deployments"][dep_num]["path_validation_results"][chain_name].append(
                        {"pem": as_pem, "<div>Subject: </div>": subject, "<div>Serial number: </div>": serial, "<div>Issuer: </div>": cert_authority})
    return (cert)


def formatDate(date):
    date = date[0:-9]
    date = (datetime.strptime(date, '%Y-%m-%d').strftime('%B %d, %Y'))
    return date


def getExpirationDays(date):
    date = date[0:-9]
    expiring_in_days = (datetime.strptime(
        date, '%Y-%m-%d') - datetime.today()).days
    date = (datetime.strptime(date, '%Y-%m-%d').strftime('%B %d, %Y'))
    date_and_days = date+" (Expiring in "+str(expiring_in_days)+" days)"
    return(str(date_and_days))


class CertInformation:
    def __init__(self, website, port):
        self.website = website
        self.port = port
        self.certExpirationDate = ""

    def getCertStatus(self):
        certs = getCert(self.website, self.port)
        cert_data_json = json.loads(json.dumps(certs))
        present_date = datetime.now()
        cert_expiration_date = cert_data_json['cert_deployments'][0]['received_certificate_chain'][0]['expiration_date']
        #print(datetime.strptime(cert_expiration_date,"%Y-%m-%d"))
        cert_expiration_date = parser.parse(cert_expiration_date)
        self.certExpirationDate = cert_expiration_date
        print(present_date)
        print(cert_expiration_date)
        if(present_date < cert_expiration_date):
            return True
        else:
            return False
     
    def getExpirationDate(self):
        return self.certExpirationDate
    


   



def getProtocol(website, port, protocol):
    supported_suites = {protocol: []}
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
    elif(protocol == "tls_compression"):
        command = ScanCommand.TLS_COMPRESSION
    elif(protocol == "tls_1_3_early_data"):
        command = ScanCommand.TLS_1_3_EARLY_DATA
    elif(protocol == "openssl_ccs_injection"):
        command = ScanCommand.OPENSSL_CCS_INJECTION
    elif(protocol == "tls_fallback_scsv"):
        command = ScanCommand.TLS_FALLBACK_SCSV
    elif(protocol == "heartbleed"):
        command = ScanCommand.HEARTBLEED
    elif(protocol == "robot"):
        command = ScanCommand.ROBOT
    elif(protocol == "session_renegotiation"):
        command = ScanCommand.SESSION_RENEGOTIATION
    elif(protocol == "session_resumption"):
        command = ScanCommand.SESSION_RESUMPTION
    elif(protocol == "session_resumption_rate"):
        command = ScanCommand.SESSION_RESUMPTION_RATE
    elif(protocol == "http_headers"):
        command = ScanCommand.HTTP_HEADERS
    elif(protocol == "elliptic_curves"):
        command = ScanCommand.ELLIPTIC_CURVES

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

    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
        website, port)
    server_info = ServerConnectivityTester().perform(server_location)
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        #server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,ScanCommand.SSL_3_0_CIPHER_SUITES,ScanCommand.TLS_1_0_CIPHER_SUITES,ScanCommand.TLS_1_1_CIPHER_SUITES,ScanCommand.TLS_1_2_CIPHER_SUITES,ScanCommand.TLS_1_3_CIPHER_SUITES},
        server_info=server_info, scan_commands={command},)
    scanner.queue_scan(server_scan_req)

    for server_scan_result in scanner.get_results():
        cipher_result = server_scan_result.scan_commands_results[command]
        
        accepted_ciphers = ""
      
        while protocol not in ["tls_compression", "tls_1_3_early_data","openssl_ccs_injection","tls_fallback_scsv","heartbleed","robot","session_renegotiation","session_resumption","session_resumption_rate","http_headers","elliptic_curves"]:
            for accepted_cipher_suite in cipher_result.accepted_cipher_suites:
                accepted_ciphers += (accepted_cipher_suite.cipher_suite.name+", ")
                supported_suites[protocol].append(
                    accepted_cipher_suite.cipher_suite.name)
            if(supported_suites[protocol]):
                cipher_suites = ""
                for cipher in supported_suites[protocol]:
                    cipher_suites += "</br>"+cipher
            else:
                cipher_suites = "Protocol not supported"

            return(cipher_suites)
        else:
            return(cipher_result)



def checkIP(Ip):
    # pass the regular expression
    # and the string in search() method
    if(re.search(regex, Ip)):
        print("Valid Ip address")
    else:
        print("Invalid Ip address")


def getSerialHex(cert_serial):
    cert_serial_hex = hex(cert_serial)
    cert_serial_hex = str(0)+(cert_serial_hex[2:]).upper()
    return cert_serial_hex


def getCertificateAuthority(serial_number_hex):
    filtered = fnmatch.filter(df.index.values, '*'+serial_number_hex)
    if(filtered):
        cert_organization = df.loc[filtered[0]
                                   ]['Certificate Subject Organization']
        ca_status = valid_svg
    else:
        cert_organization = "Unknown"
        ca_status = invalid_svg
    return(cert_organization)
