"""Legacy filename: construct a small offline TCP PCAP; never transmit packets."""
import argparse
from pathlib import Path

def write_capture(path,count=5):
    if not 1<=count<=50:
        raise ValueError('count must be between 1 and 50')
    from scapy.all import Ether, IP, TCP, PcapWriter
    with Path(path).open('xb') as stream:
        writer=PcapWriter(stream,linktype=1,sync=True)
        try:
            for index in range(count):
                packet=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='192.0.2.2')/TCP(sport=40000+index,dport=600,flags='S')
                packet.time=index
                writer.write(packet)
        finally:
            writer.close()

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--count',type=int,choices=range(1,51),default=5,metavar='1..50')
    args=parser.parse_args(argv)
    try:
        write_capture(args.output,args.count)
        print(f'Saved {args.count} synthetic packets to {args.output}; no traffic sent')
        return 0
    except (ImportError,OSError,ValueError) as exc:
        parser.exit(2,f'error: {exc}; install scapy for PCAP support\n')

if __name__ == '__main__':
    raise SystemExit(main())
