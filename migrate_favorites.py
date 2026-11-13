#!/usr/bin/env python3
"""Explicit, non-destructive favorites import; dry-run unless --apply is supplied."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import tempfile

import favorites_store
from configuration import CONFIG


def parse_legacy(text, local_node):
    """Decode paired INI entries without silently dropping duplicates or commands."""
    section, pending = '', None
    entries = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith((';', '#')):
            continue
        if line.startswith('[') and line.endswith(']'):
            if pending is not None:
                raise ValueError(f'Unpaired label before line {number}')
            section = line[1:-1].strip()
            continue
        if section not in ('general', local_node):
            continue
        label = favorites_store.LABEL.fullmatch(line)
        if label:
            if pending is not None:
                raise ValueError(f'Unpaired label at line {number}')
            # Only the writer's quote/backslash escapes; never unicode_escape.
            pending = re.sub(r'\\([\\"])', r'\1', label.group(1))
            continue
        command = favorites_store.CMD.fullmatch(line)
        if command:
            match = re.fullmatch(r'rpt\s+cmd\s+(?:%node%|[0-9]{3,7})\s+ilink\s+3\s+([0-9]{4,7})', command.group(1), re.I)
            if not match or pending is None:
                raise ValueError(f'Unsupported/unpaired command at line {number}')
            node = match.group(1)
            # Legacy writer appends a node number to the label, not description.
            name = re.sub(r'\s+' + re.escape(node) + r'\s*$', '', pending)
            entries.append({'node': node, 'name': name})
            pending = None
        elif line.lower().startswith(('label[', 'cmd[')):
            raise ValueError(f'Unsupported favorites syntax at line {number}')
    if pending is not None:
        raise ValueError('Unpaired final label')
    if not entries:
        raise ValueError('No favorites found; use an explicit [] JSON file to initialize empty')
    return favorites_store.validate(entries)


def migrate(source, destination=None, *, apply=False, source_format='auto', local_node=None):
    source = Path(source)
    destination = Path(destination) if destination is not None else favorites_store.JSON_PATH
    raw = source.read_bytes()
    text = raw.decode('utf-8')
    if source_format == 'auto':
        source_format = 'json' if text.lstrip().startswith('[') and not re.match(r'\s*\[[A-Za-z0-9_-]+\]', text) else 'ini'
    if source_format not in ('json', 'ini'):
        raise ValueError('Source format must be auto, json, or ini')
    entries = (favorites_store.validate(json.loads(text)) if source_format == 'json'
               else parse_legacy(text, local_node or CONFIG['allstar']['local_node']))

    def check_existing():
        if destination.is_symlink():
            raise ValueError('Refusing a symlink destination')
        if destination.exists():
            existing = favorites_store.validate(json.loads(destination.read_text(encoding='utf-8')))
            if existing != entries:
                raise ValueError('Destination already contains different favorites; no files changed')
            return True
        return False

    result = {'count': len(entries), 'destination': str(destination), 'status': 'dry-run'}
    if check_existing():
        return result | {'status': 'unchanged'}
    if not apply:
        return result
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    with (destination.parent/'favorites.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if check_existing():
            return result | {'status': 'unchanged'}
        if source.read_bytes() != raw:
            raise ValueError('Source changed during migration; retry after reviewing it')
        # Backup the exact source bytes before publishing a destination. Never overwrite.
        fd, backup = tempfile.mkstemp(prefix='favorites-source-', suffix='.bak', dir=destination.parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        fd, temporary = tempfile.mkstemp(prefix='.migration-', dir=destination.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(entries, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o640)
            # Atomic, no-clobber publish even against a non-cooperating creator.
            os.link(temporary, destination)
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.unlink(temporary)
    return result | {'status': 'imported', 'backup': backup}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--format', choices=('auto', 'json', 'ini'), default='auto')
    parser.add_argument('--local-node', help='Include this legacy node-specific INI section')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        result = migrate(args.source, args.destination, apply=args.apply,
                         source_format=args.format, local_node=args.local_node)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Migration failed: {exc}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
