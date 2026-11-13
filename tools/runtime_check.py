#!/usr/bin/env python3
"""Read-only packaging checks; never submits a radio control command."""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

APP=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(APP))
from configuration import CONFIG, require_node


def validate():
    from favorites_store import read
    from security import Credentials
    require_node()
    read()
    Credentials(CONFIG['auth']['credentials_file'])
    for path in (Path(CONFIG['paths']['monitor_state_dir'])/'monitor-history.json',):
        if path.exists():
            try:
                data=json.loads(path.read_bytes())
            except (ValueError,UnicodeError):
                continue # retained for diagnosis; monitor already handles damaged history
            if isinstance(data,dict) and data.get('version',1)!=1:
                raise ValueError('Unsupported history version; explicit migration required')


def wait_socket():
    settings=CONFIG['broker']
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        try:
            info=Path(settings['socket_path']).stat()
            if (stat.S_ISSOCK(info.st_mode) and info.st_uid==settings['service_uid'] and
                    info.st_gid==settings['socket_gid'] and stat.S_IMODE(info.st_mode)==0o660):
                return
        except FileNotFoundError:
            pass
        time.sleep(.1)
    raise ValueError('Control socket did not become ready')


def wait_web():
    host=CONFIG['web']['bind']
    host='127.0.0.1' if host=='0.0.0.0' else host
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        try:
            connection=http.client.HTTPConnection(host,CONFIG['web']['port'],timeout=1)
            try:
                connection.request('GET','/login',headers={'Host':f'localhost:{CONFIG["web"]["port"]}'})
                response=connection.getresponse()
                # A strict proxy-only configuration can correctly deny this direct probe.
                if response.status in (200,403) and response.getheader('Server','').startswith('HubScanner'):
                    return
            finally:
                connection.close()
        except (OSError,http.client.HTTPException):
            pass
        time.sleep(.1)
    raise ValueError('Web interface did not become ready')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('check',choices=('validate','socket','web'))
    args=parser.parse_args()
    try:
        {'validate':validate,'socket':wait_socket,'web':wait_web}[args.check]()
    except (OSError,ValueError,KeyError,TypeError):
        parser.exit(1,'Runtime validation failed; inspect configuration, permissions and service logs.\n')


if __name__=='__main__':
    main()
