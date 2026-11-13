#!/usr/bin/env python3
"""Offline development checks; does not execute application entry points."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    # Phase 1 hashes remain a historical artifact, not a post-Phase-1 edit ban.
    trees = {}
    for path in ROOT.glob('*.py'):
        trees[path.name] = ast.parse(path.read_text(), filename=path.name)
    print(f'Python syntax OK ({len(trees)} runtime/tool modules)', flush=True)
    for folder in ('tests', 'tools', 'acceptance'):
        for path in (ROOT/folder).glob('*.py'):
            ast.parse(path.read_text(), filename=str(path))
    # Never inherit a deployment config into regression tests.
    os.environ['KC1RAY_CONFIG'] = str(ROOT/'config/config.example.toml')
    sys.path.insert(0, str(ROOT))
    import dashboard
    html = dashboard.render_html()
    import re
    from web_auth import LOGIN_HTML
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html+LOGIN_HTML, re.S)

    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node.js required for JavaScript syntax check; no checks skipped')
    for js in scripts:
        subprocess.run([node, '--check', '-'], input=js, text=True, check=True, timeout=30)
    print('Embedded JavaScript syntax OK', flush=True)
    from configuration import load_config
    config = load_config(ROOT/'config/config.example.toml')
    if (config['web']['bind'] != '127.0.0.1'
            or config['web']['controls_enabled'] or config['web']['allow_lan_http']):
        raise ValueError('Example must retain secure defaults')
    if config['allstar']['local_node']:
        raise ValueError('Example requires explicit node setup')
    if json.loads((ROOT/'config/favorites.example.json').read_text()) != []:
        raise ValueError('Favorites example must not contain deployment favorites')
    print('Configuration examples parse and retain proposed secure defaults', flush=True)
    subprocess.run(['sh','-n',str(ROOT/'install.sh')],check=True,timeout=30)
    analyzer=shutil.which('systemd-analyze')
    if not analyzer:
        raise RuntimeError('systemd-analyze required for packaging unit verification')
    with tempfile.TemporaryDirectory(prefix='kc1ray-unit-check-') as directory:
        folder=Path(directory)
        for source in (ROOT/'packaging/systemd').glob('*.in'):
            (folder/source.name.removesuffix('.in')).write_text(source.read_text().replace('@ASTERISK_GROUP@','asterisk'))
        (folder/'asterisk.service').write_text('[Unit]\nDescription=Offline syntax stub\n[Service]\nExecStart=/usr/bin/true\n')
        env=os.environ | {'SYSTEMD_UNIT_PATH':directory+':/usr/lib/systemd/system:/lib/systemd/system'}
        subprocess.run([analyzer,'verify','--man=no','--generators=no',
                        *[str(path) for path in folder.glob('kc1ray*.service')],
                        *[str(path) for path in folder.glob('*.timer')]],env=env,check=True,timeout=30)
    with tempfile.TemporaryDirectory(prefix='kc1ray-recovery-check-') as directory:
        broken=Path(directory)/'broken.toml'
        broken.write_text('deliberately invalid [')
        subprocess.run([sys.executable,'-B',str(ROOT/'tools/installer.py'),'--help'],
                       env=os.environ | {'KC1RAY_CONFIG':str(broken)},stdout=subprocess.DEVNULL,check=True,timeout=30)
    print('Shell syntax, systemd unit verification and recovery CLI bootstrap OK',flush=True)
    subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                    '-s', 'tests', '-v'], cwd=ROOT, check=True, timeout=180)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f'Check failed: {exc}', file=sys.stderr)
        sys.exit(1)
