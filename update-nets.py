#!/usr/bin/env python3
"""Download the AllStar Nets weekly schedule once per day and cache locally.

This is a best-effort HTML parser of a third-party site, not an official API.
On fetch/parse failures the previous good schedule is retained.
"""
import json
import os
import re
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from configuration import CONFIG
from urllib.parse import urljoin

SOURCE = CONFIG['schedules']['allstarnets']
URL = SOURCE['url']
DEST = Path(CONFIG['paths']['cache_dir']) / 'nets.json'

DAYS = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
PATTERN = re.compile(r'\bNode\s+(\d{4,7})\s+(.+?)\s+(\d{1,2}:\d{2})\s*UTC\b', re.I)


class NetsParser(HTMLParser):
    """Capture day headings and link text in document order."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.records = []
        self.day = None
        self.capture = []
        self.tag = None
        self.href = None
        self.start_depth = 0
        self.depth = 0

    def handle_starttag(self, tag, attrs):
        self.depth += 1
        if self.tag is None and tag in ('h1', 'h2', 'h3', 'a'):
            self.tag = tag
            self.capture = []
            self.start_depth = self.depth
            self.href = dict(attrs).get('href', '') if tag == 'a' else ''

    def handle_data(self, data):
        if self.tag is not None:
            self.capture.append(data)

    def handle_endtag(self, tag):
        if tag == self.tag and self.depth == self.start_depth:
            content = ' '.join(' '.join(self.capture).split())
            if self.tag in ('h1', 'h2', 'h3'):
                for weekday in DAYS:
                    if re.search(r'\b' + weekday + r'\b', content, re.I):
                        self.day = DAYS.index(weekday)
                        break
            elif self.tag == 'a' and self.day is not None:
                match = PATTERN.search(content)
                if match:
                    node, name, clock = match.groups()
                    hour, minute = map(int, clock.split(':'))
                    if hour < 24 and minute < 60:
                        url = self.href if self.href.startswith(SOURCE['details_url']) else ''
                        if self.href.startswith('/net/'):
                            url = urljoin(SOURCE['details_url'], self.href.lstrip('/'))
                        self.records.append({
                            'node': node, 'name': name.strip(),
                            'weekday': self.day, 'start_utc': f'{hour:02d}:{minute:02d}',
                            'url': url,
                        })
            self.tag = None
            self.capture = []
        self.depth = max(0, self.depth - 1)


def parse_page(html):
    parser = NetsParser()
    parser.feed(html)
    unique = {(r['weekday'], r['start_utc'], r['node'], r['name']): r
              for r in parser.records}
    records = sorted(unique.values(), key=lambda r: (r['weekday'], r['start_utc'], r['node']))
    # A substantial drop indicates HTML changes or a truncated response.
    if len(records) < 15 or len(set(r['weekday'] for r in records)) < 5:
        raise ValueError(f'Unexpected schedule format: {len(records)} events across '
                         f'{len(set(r["weekday"] for r in records))} days')
    return records


def main():
    if not SOURCE['enabled']:
        print('Schedule source disabled; cache left unchanged')
        return
    req = urllib.request.Request(URL, headers={'User-Agent': 'KC1RAY-Hub-Scanner/1.0 (daily schedule download)', 'Accept': 'text/html'})
    with urllib.request.urlopen(req, timeout=SOURCE['request_timeout_seconds']) as resp:
        if resp.status != 200:
            raise ValueError(f'HTTP {resp.status}')
        html = resp.read(3_000_001)
    if len(html) > 3_000_000:
        raise ValueError('Response too large')
    records = parse_page(html.decode('utf-8'))
    result = {'source': URL, 'updated': int(datetime.now(timezone.utc).timestamp()),
              'default_duration_minutes': SOURCE['estimated_duration_minutes'], 'nets': records}
    DEST.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.nets-', suffix='.json', dir=DEST.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(result, out, indent=2)
            out.write('\n')
        os.chmod(tmp, 0o644)
        os.replace(tmp, DEST)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(f'Saved {len(records)} weekly net events to {DEST}')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Net schedule update FAILED; old cache retained: {exc}', file=sys.stderr)
        sys.exit(1)
