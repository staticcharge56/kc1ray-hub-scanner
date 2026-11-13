"""KC1RAY favorites persisted independently from AllScan.

The configured state directory must be writable by the application identity.
"""
from pathlib import Path
import fcntl
import json
import os
import re
import tempfile

from configuration import CONFIG

BASE = Path(CONFIG['paths']['state_dir'])
JSON_PATH = BASE / 'favorites.json'
LOCK = BASE / 'favorites.lock'
NODE = re.compile(r'^[0-9]{4,7}$')
LABEL = re.compile(r'^\s*label\[\]\s*=\s*"((?:[^"\\]|\\.)*)"\s*(?:;.*)?$', re.I)
CMD = re.compile(r'^\s*cmd\[\]\s*=\s*"([^"\n]*)"\s*(?:;.*)?$', re.I)
CONNECT = re.compile(r'\bilink\s+3\s+([0-9]{4,7})\b', re.I)


def _valid_name(name):
    if not isinstance(name, str) or not name.strip() or len(name) > 160 or any(ord(c) < 32 for c in name):
        raise ValueError('Name must be between 1 and 160 printable characters')
    return name.strip()


def _valid_node(node):
    if not isinstance(node, str) or not NODE.fullmatch(node):
        raise ValueError('Node must contain 4–7 digits')
    return node


def parse_original(contents):
    """Legacy parser compatibility; use migrate_favorites for strict safe imports."""
    section = None
    pending = None
    entries = []
    seen = set()
    for raw in contents.splitlines():
        line = raw.strip()
        if not line or line.startswith((';', '#')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].strip().lower()
            pending = None
            continue
        if section != 'general':
            continue
        lm = LABEL.match(line)
        if lm:
            pending = re.sub(r'\\([\\"])', r'\1', lm.group(1))
            continue
        cm = CMD.match(line)
        if cm:
            match = CONNECT.search(cm.group(1))
            if match:
                node = match.group(1)
                if node not in seen:
                    # Keep original name/description but remove duplicate trailing node number.
                    name = (pending or 'Node ' + node).strip()
                    name = re.sub(r'\s+' + re.escape(node) + r'\s*$', '', name).strip() or 'Node ' + node
                    entries.append({'node': node, 'name': _valid_name(name)})
                    seen.add(node)
            pending = None
    if not entries:
        raise ValueError('No AllStar favorites could be read from the AllScan file')
    return entries


def _read():
    data = json.loads(JSON_PATH.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError('Favorites file must be a JSON array')
    return validate(data)


def read():
    return _read()


def _atomic(path, content):
    fd, tmp = tempfile.mkstemp(prefix='.fav-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def validate(entries):
    if not isinstance(entries, list):
        raise ValueError('Favorites must be a JSON array')
    if len(entries) > 250:
        raise ValueError('Maximum 250 favorites')
    seen = set()
    clean = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'node', 'name'}:
            raise ValueError('Each favorite must contain only node and name')
        node = _valid_node(entry['node'])
        _valid_name(entry['name'])
        name = entry['name']
        if node in seen:
            raise ValueError('Duplicate node: ' + node)
        seen.add(node)
        clean.append({'node': node, 'name': name})
    return clean


def save(entries):
    """Serialized atomic replacement; never produce a second authoritative file."""
    with LOCK.open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _save_unlocked(entries)


def _save_unlocked(entries):
    clean = validate(entries)
    _atomic(JSON_PATH, json.dumps(clean, indent=2, ensure_ascii=False) + '\n')
    return clean


def mutate(payload):
    if not isinstance(payload, dict):
        raise ValueError('Favorites request must be an object')
    with LOCK.open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        entries = _read()
        action = payload.get('action')
        if action == 'add':
            node = _valid_node(payload.get('node'))
            name = _valid_name(payload.get('name'))
            if any(e['node'] == node for e in entries):
                raise ValueError('That node is already a favorite')
            entries.append({'node': node, 'name': name})
        elif action in ('edit', 'remove', 'up', 'down'):
            node = _valid_node(payload.get('node'))
            idx = next((i for i,e in enumerate(entries) if e['node'] == node), None)
            if idx is None:
                raise ValueError('Favorite not found')
            if action == 'edit':
                entries[idx]['name'] = _valid_name(payload.get('name'))
            elif action == 'remove':
                del entries[idx]
            elif action == 'up' and idx > 0:
                entries[idx - 1], entries[idx] = entries[idx], entries[idx - 1]
            elif action == 'down' and idx + 1 < len(entries):
                entries[idx + 1], entries[idx] = entries[idx], entries[idx + 1]
        else:
            raise ValueError('Unrecognized favorites action')
        return _save_unlocked(entries)
