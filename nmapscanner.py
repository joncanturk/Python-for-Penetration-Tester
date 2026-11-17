"""Run one bounded TCP-connect scan or inspect an existing Nmap XML file."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

def validate_target(value):
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if len(value) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in value.split('.')):
            return value
    raise argparse.ArgumentTypeError('provide a single IP or hostname, not a range, URL or option')

def parse_ports(value):
    try:
        ports=sorted(set(int(p) for p in value.split(',')))
        if not ports or len(ports)>100 or any(p<1 or p>65535 for p in ports):
            raise ValueError
        return ','.join(map(str,ports))
    except ValueError:
        raise argparse.ArgumentTypeError('provide at most 100 comma-separated ports from 1 to 65535')

def parse_xml(text):
    root=ET.fromstring(text)
    if root.tag != 'nmaprun':
        raise ValueError('expected an Nmap XML document')
    hosts=[]
    for host in root.findall('host'):
        status=host.find('status')
        hosts.append({'addresses':[a.get('addr') for a in host.findall('address')],
                      'status':status.get('state','unknown') if status is not None else 'unknown',
                      'ports':[{'port':int(p.get('portid')), 'protocol':p.get('protocol'),
                                'state':p.find('state').get('state','unknown') if p.find('state') is not None else 'unknown'} for p in host.findall('ports/port')],
                      'extraports':[dict(p.attrib) for p in host.findall('ports/extraports')]})
    return {'hosts':hosts}

def scan(target, ports, timeout=60):
    target=validate_target(target)
    ports=parse_ports(ports)
    command=['nmap', '-sT', '-n', '-p', ports, '--host-timeout', str(timeout)+'s', '-oX', '-']
    try:
        if ipaddress.ip_address(target).version == 6:
            command.append('-6')
    except ValueError:
        pass
    command.append(target)
    completed=subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout+5)
    return parse_xml(completed.stdout)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', type=validate_target)
    parser.add_argument('--xml', type=Path, help='offline XML input; no scan runs')
    parser.add_argument('--ports', type=parse_ports, default='21,22,80,139,443,8080')
    parser.add_argument('--timeout', type=int, choices=range(1,121), default=60, metavar='1..120')
    args=parser.parse_args(argv)
    if bool(args.target)==bool(args.xml):
        parser.error('provide exactly one target or --xml')
    try:
        result=parse_xml(args.xml.read_text(encoding='utf-8')) if args.xml else scan(args.target,args.ports,args.timeout)
        print(json.dumps(result,indent=2))
        return 0
    except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError) as exc:
        parser.exit(2,f'error: {exc} (live scans require Nmap on PATH)\n')

if __name__ == '__main__':
    raise SystemExit(main())
