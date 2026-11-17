"""List advertised SSIDs from an existing 802.11 capture; no live sniffing."""
import argparse
import json
from pathlib import Path

def extract_ssid(packet):
    from scapy.layers.dot11 import Dot11, Dot11Elt
    frame=packet.getlayer(Dot11)
    if frame is None or frame.type!=0 or frame.subtype not in (0,2,4,5,8):
        return None
    element=packet.getlayer(Dot11Elt)
    while isinstance(element,Dot11Elt):
        if element.ID==0:
            return bytes(element.info).decode('utf-8',errors='replace') or None
        element=element.payload
    return None

def read_ssids(path):
    from scapy.utils import PcapReader
    result=set()
    with PcapReader(str(path)) as packets:
        for packet in packets:
            ssid=extract_ssid(packet)
            if ssid is not None:
                result.add(ssid)
    return sorted(result)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap',type=Path)
    args=parser.parse_args(argv)
    try:
        print(json.dumps({'ssids':read_ssids(args.pcap)},ensure_ascii=True,indent=2))
        return 0
    except (ImportError,OSError,ValueError) as exc:
        parser.exit(2,f'error: {exc}; install scapy and supply an 802.11 capture\n')

if __name__ == '__main__':
    raise SystemExit(main())
