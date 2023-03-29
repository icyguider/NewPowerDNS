# NewPowerDNS
NewPowerDNS is an updated version of [@domchell's](https://github.com/dmchell) [PowerDNS](https://github.com/mdsecactivebreach/PowerDNS). The main feature added is support for transferring files using DNS A records. See below for a complete list of the modifications made:
- Support for transfer over DNS A records
- Gzip compression to reduce file transfer size
- Support for transferring all types of files
- New stagers that can be easily obfuscated or ran line-by-line to evade being blocked by AV/EDR
- Options to print, exec, or save transferred file
- Update to python3 from python2

The only dependency besides python3 is scapy. It can easily be installed via pip like so:
```
python3 -m pip install scapy
```

See below for a video demonstrating transferring files over both DNS A and TXT records:
<video src="https://user-images.githubusercontent.com/79864975/228629419-fc982219-57ca-48e2-b3f1-fd54d9879837.mp4"></video>

## Examples & Usage
Transfer powershell script over DNS A records and print to console:
```
python3 NewPowerDNS.py --file AmSeeETWBP.ps1 --domain sub.domain.com -r A -a print
```

Transfer exe file over DNS TXT records and save to disk:
```
python3 NewPowerDNS.py --file SharpHound.exe --domain sub.domain.com -r TXT -a save
```

Transfer powershell script over DNS TXT records and automatically load into memory:
```
python3 NewPowerDNS.py --file Invoke-Seatbelt.ps1 --domain sub.domain.com -r TXT -a exec
```

General usage:
```

 ___                        ___  _ _  ___
| . \ ___  _ _ _  ___  _ _ | . \| \ |/ __>
|  _// . \| | | |/ ._>| '_>| | ||   |\__ \
|_|  \___/|__/_/ \___.|_|  |___/|_\_|<___/

DNS A Record & updated stager version by @icyguider
        Original version by @domchell


usage: NewPowerDNS.py [-h] [-f <file>] [-d <domain>] [-a <action>] [-r <record-type>] [-i <interface>]

optional arguments:
  -h, --help            show this help message and exit
  -f <file>, --file <file>
                        file to transfer
  -d <domain>, --domain <domain>
                        domain with auth NS record
  -a <action>, --action <action>
                        action to perform once data is transferred (options: save, exec, print)
  -r <record-type>, --record-type <record-type>
                        type of DNS record to use for transfer (options: A, TXT) (default: TXT)
  -i <interface>, --interface <interface>
                        interface to bind to (default: eth0)
```

