"""Generate a locally administered unicast MAC; optionally apply it on Linux."""
import argparse
import json
import re
import secrets
import subprocess
import sys

def new_mac():
    value=bytearray(secrets.token_bytes(6))
    value[0]=(value[0] | 2) & 254
    return ':'.join(f'{b:02x}' for b in value)

def apply_mac(interface, address):
    if sys.platform != 'linux':
        raise ValueError('--apply is supported only on Linux with iproute2 and suitable privileges')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',interface) or interface.startswith('-'):
        raise ValueError('invalid interface name')
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',address):
        raise ValueError('invalid MAC address')
    def run(*args):
        return subprocess.run(['ip',*args],check=True,capture_output=True,text=True,timeout=10)
    original=json.loads(run('-j','link','show','dev',interface).stdout)
    if len(original)!=1:
        raise ValueError('interface not uniquely identified')
    was_up='UP' in original[0].get('flags',[])
    if was_up:
        run('link','set','dev',interface,'down')
    try:
        run('link','set','dev',interface,'address',address)
    finally:
        if was_up:
            run('link','set','dev',interface,'up')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface')
    parser.add_argument('--apply',action='store_true',help='change the selected Linux interface; may interrupt connectivity')
    args=parser.parse_args(argv)
    if args.apply and not args.interface:
        parser.error('--apply requires --interface')
    try:
        address=new_mac()
        if args.apply:
            apply_mac(args.interface,address)
        print(json.dumps({'mac':address,'applied':args.apply,'interface':args.interface}))
        return 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        parser.exit(2,f'error: {exc}\n')

if __name__ == '__main__':
    raise SystemExit(main())
