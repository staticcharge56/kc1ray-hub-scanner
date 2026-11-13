#!/usr/bin/env python3
"""Create/reset local administrator credentials interactively; never accept a password argument."""
import argparse
import getpass
import sys
from pathlib import Path
from configuration import CONFIG
from security import create_credentials


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials',type=Path,default=Path(CONFIG['auth']['credentials_file']))
    parser.add_argument('--username',default='admin')
    parser.add_argument('--replace',action='store_true',help='Explicitly replace an existing hash; restart the web process to invalidate sessions')
    args=parser.parse_args()
    if not sys.stdin.isatty():
        parser.exit(1,'Administrator setup requires an interactive terminal for hidden passphrase entry.\n')
    try:
        password=getpass.getpass('New administrator passphrase (15+ characters): ')
        confirmation=getpass.getpass('Confirm passphrase: ')
        if password!=confirmation:
            raise ValueError('Passphrases do not match')
        create_credentials(args.credentials,args.username,password,replace=args.replace)
    except (OSError,ValueError) as exc:
        parser.exit(1,'Administrator setup failed: '+str(exc)+'\n')
    print('Administrator credentials saved privately. Restart the web process after a reset.')


if __name__=='__main__':
    main()
