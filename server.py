"""Serve one greeting on loopback, with bounded accept and send timeouts."""
import argparse
import socket

def serve(port=9337,timeout=15):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.settimeout(timeout)
        server.bind(('127.0.0.1',port))
        server.listen(1)
        print(f'Listening on 127.0.0.1:{server.getsockname()[1]}',flush=True)
        connection,address=server.accept()
        with connection:
            connection.settimeout(timeout)
            connection.sendall(f'Thank you for connecting {address[0]}\n'.encode('utf-8'))

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=9337)
    parser.add_argument('--timeout',type=int,choices=range(1,61),default=15,metavar='1..60')
    args=parser.parse_args(argv)
    if not 0<=args.port<=65535:
        parser.error('port must be between 0 and 65535')
    try:
        serve(args.port,args.timeout)
        return 0
    except OSError as exc:
        parser.exit(2,f'error: {exc}\n')

if __name__ == '__main__':
    raise SystemExit(main())
