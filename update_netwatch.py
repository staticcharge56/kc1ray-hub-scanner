#!/usr/bin/env python3
"""Cache only approved, published AllStar occurrences from NetWatch.
No calls to NetLogger or AllStarLink stats. Standard-library only.
"""
import json
import os
import re
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from configuration import CONFIG
from urllib.parse import urljoin

SOURCE = CONFIG['schedules']['netwatch']
URL = SOURCE['url']
OUT = Path(CONFIG['paths']['cache_dir']) / 'netwatch-nets.json'



def iso_time(value):
    if not isinstance(value, str):
        raise ValueError('Missing timestamp')
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Timestamp has no timezone')
    return dt.timestamp()


def parse(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('nets'), list):
        raise ValueError('Invalid NetWatch API structure')
    generated_at = payload.get('generatedAt')
    gen_seconds = iso_time(generated_at)
    now = time.time()
    if abs(now - gen_seconds) > 2 * 3600:
        raise ValueError('NetWatch API generatedAt is stale or in the future')
    nets = []
    seen = set()
    for item in payload['nets']:
        if not isinstance(item, dict):
            continue
        if item.get('sourceName') != 'Netwatch directory' or item.get('statusBasis') != 'Approved schedule':
            continue
        try:
            start = iso_time(item.get('start'))
            end = iso_time(item.get('end'))
        except (ValueError, TypeError):
            continue
        if end <= start or end - start > 24 * 3600:
            continue
        title = str(item.get('name') or '').strip()
        if not title:
            continue
        nodes = set()
        connections = item.get('connections')
        if not isinstance(connections, list):
            continue
        for connection in connections:
            if not isinstance(connection, dict) or str(connection.get('mode', '')).strip().lower() != 'allstar':
                continue
            # Numeric AllStar node IDs, potentially several in one connection string.
            nodes.update(re.findall(r'(?<!\d)\d{3,7}(?!\d)', str(connection.get('connection') or '')))
        for node in sorted(nodes):
            identity = (str(item.get('listingId') or item.get('identity') or title), node, start, end)
            if identity in seen:
                continue
            seen.add(identity)
            directory_url = item.get('directoryUrl') or item.get('sourceUrl') or ''
            if isinstance(directory_url, str) and directory_url.startswith('directory-view.php?id='):
                directory_url = SOURCE['details_url'] + directory_url
            elif not isinstance(directory_url, str) or not directory_url.startswith(SOURCE['details_url']):
                directory_url = urljoin(SOURCE['details_url'], 'directory-view.php')
            nets.append({
                'node': node, 'name': title, 'start': item['start'], 'end': item['end'],
                'url': directory_url, 'listing_id': str(item.get('listingId') or ''),
                'source': 'NetWatch',
            })
    nets.sort(key=lambda n: (n['start'], n['name'], n['node']))
    return {'updated': int(now), 'generated_at': generated_at, 'source': 'NetWatch', 'nets': nets}


def main():
    if not SOURCE['enabled']:
        print('Schedule source disabled; cache left unchanged')
        return
    req = urllib.request.Request(URL, headers={'User-Agent': 'KC1RAY-HubScanner-NetWatch/1.0', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=SOURCE['request_timeout_seconds']) as response:
        if response.status != 200:
            raise RuntimeError(f'HTTP {response.status}')
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('API payload too large')
    data = parse(json.loads(raw))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix='.netwatch-', suffix='.tmp', dir=OUT.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_name, 0o640)
        os.replace(temp_name, OUT)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    print(f"NetWatch: cached {len(data['nets'])} AllStar node/occurrences; last updated {data['generated_at']}", flush=True)


if __name__ == '__main__':
    main()
