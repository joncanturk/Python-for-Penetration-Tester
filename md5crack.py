"""Offline MD5 wordlist demonstration; MD5 is not suitable for password storage."""
import argparse
import hashlib
import json
from pathlib import Path
import re

def find_match(digest, candidates):
    if not re.fullmatch(r"[0-9a-fA-F]{32}", digest):
        raise ValueError("MD5 must contain exactly 32 hexadecimal characters")
    for candidate in candidates:
        candidate = candidate.rstrip("\r\n")
        if hashlib.md5(candidate.encode("utf-8"), usedforsecurity=False).hexdigest() == digest.lower():
            return candidate
    return None

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-md5', '--md5', required=True)
    parser.add_argument('-w', '--wordlist', required=True, type=Path)
    args=parser.parse_args(argv)
    try:
        with args.wordlist.open(encoding='utf-8') as stream:
            match=find_match(args.md5, stream)
        print(json.dumps({'matched': match is not None, 'value': match}))
        return 0 if match is not None else 1
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f'error: {exc}\n')

if __name__ == '__main__':
    raise SystemExit(main())
