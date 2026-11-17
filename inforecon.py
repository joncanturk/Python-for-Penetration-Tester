"""Inspect HTTP response headers for one explicitly provided URL."""
import argparse
import json
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def validate_url(value):
    parts=urlsplit(value)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password or any(c.isspace() for c in value):
        raise ValueError('use an http(s) URL without credentials or whitespace')
    _=parts.port
    return value

def inspect_headers(url, timeout=10):
    url=validate_url(url)
    opener=build_opener(NoRedirect())
    try:
        response=opener.open(Request(url,method='HEAD'),timeout=timeout)
    except HTTPError as exc:
        response=exc
    with response:
        return {'url':url,'status':response.code,'headers':list(response.headers.items())}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--timeout',type=int,choices=range(1,61),default=10,metavar='1..60')
    args=parser.parse_args(argv)
    try:
        print(json.dumps(inspect_headers(args.url,args.timeout),indent=2))
        return 0
    except (OSError,ValueError,URLError) as exc:
        parser.exit(2,f'error: {exc}\n')

if __name__ == '__main__':
    raise SystemExit(main())
