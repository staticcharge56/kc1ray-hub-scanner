#!/usr/bin/python3
"""Synthetic Asterisk CLI/socket. No real Asterisk invocation or radio I/O."""
import fcntl
import json
from pathlib import Path
import re
import socket
import sys

STATE = Path('/run/asterisk/mock-links.json')


def main():
    if sys.argv[1:] == ['--socket-server']:
        with socket.socket(socket.AF_UNIX) as server:
            server.bind('/run/asterisk/asterisk.ctl')
            Path('/run/asterisk/asterisk.ctl').chmod(0o660)
            server.listen()
            while True:
                connection, _ = server.accept()
                connection.close()
    elif sys.argv[1:] == ['-V']:
        print('Asterisk 22.0.0+asl3 ACCEPTANCE MOCK ONLY')
    elif len(sys.argv) == 3 and sys.argv[1] == '-rx':
        command = sys.argv[2]
        with Path('/run/asterisk/mock.lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            links = json.loads(STATE.read_text() or '[]') if STATE.exists() else []
            if command == 'rpt show variables 1000':
                value=str(len(links))+''.join(','+node+'TU' for node in links) if links else ''
                print('RPT_ALINKS='+value)
            elif (match := re.fullmatch(r'rpt cmd 1000 ilink ([13]) ([0-9]{4,7})',command)):
                action, node = match.groups()
                if action == '3' and node not in links:
                    links.append(node)
                elif action == '1' and node in links:
                    links.remove(node)
                STATE.write_text(json.dumps(links))
                print('MOCK command accepted')
            else:
                raise SystemExit('Unsupported mock command')
    else:
        raise SystemExit('Unsupported mock CLI')


if __name__ == '__main__':
    main()
