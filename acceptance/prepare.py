#!/usr/bin/env python3
"""Create a new, allowlisted disposable-image build context; never deploy."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def prepare(destination):
    destination = Path(destination).absolute()
    if destination.exists():
        raise ValueError('Build context must not already exist')
    if destination == ROOT or ROOT in destination.parents:
        raise ValueError('Build context must be outside the source repository')
    spec = importlib.util.spec_from_file_location('acceptance_installer', ROOT/'tools/installer.py')
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    _, inventory, identity = installer.source_inventory(ROOT)
    names = set(inventory) | {'install.sh', 'config/favorites.example.json', '.gitignore',
                              'tests/fixtures/legacy-favorites.ini'}
    for folder in ('tests', 'acceptance', 'tools'):
        names.update(str(p.relative_to(ROOT)) for p in (ROOT/folder).rglob('*')
                     if p.is_file() and p.suffix in ('.py', '.json', '.md'))
    names.add('acceptance/Containerfile')
    hashes = {}
    # Validate the complete list before writing any context. No private config,
    # historical copies, runtime state, environment metadata or .git included.
    for name in names:
        path = ROOT/name
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != ROOT.parent):
            raise ValueError('Symlink in build source: '+name)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    destination.mkdir(mode=0o700)
    for name in sorted(names):
        target = destination/'source'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/name, target)
    shutil.copyfile(ROOT/'acceptance/Containerfile', destination/'Containerfile')
    (destination/'context-manifest.json').write_text(json.dumps({'release':identity,'sha256':hashes},indent=2)+'\n')
    return {'context':str(destination),'files':len(names),'release':identity}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    print(json.dumps(prepare(parser.parse_args().destination),indent=2))
