#!/usr/bin/env python3
"""KC1RAY AllStarLink favorite hub scanner."""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from configuration import CONFIG, require_node
import favorites_store
from radio_control import (Asterisk, LinkController, perform, load_selection,
                           operation_lock, command_guard)

NODE = CONFIG['allstar']['local_node']
CACHE = Path(CONFIG['paths']['cache_dir']) / 'activity.json'
STATE_DIR = Path(CONFIG['paths']['state_dir'])
STATE = STATE_DIR / 'scanner-state.json'
LOCK = Path(CONFIG['paths']['runtime_dir']) / 'scanner.lock'
ASTERISK = CONFIG['allstar']['asterisk_binary']
MAX_AGE = CONFIG['monitor']['max_stats_age_seconds']


def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def save_state(data):
    temp = STATE_DIR / f"scanner-state.{os.getpid()}.tmp"
    temp.write_text(json.dumps(data, indent=2))
    os.replace(temp, STATE)


def eligible(fav, now):
    try:
        checked = int(fav.get("checked") or 0)
        timestamp = int(fav.get("stats_time") or 0)
        return (
            fav.get("activity") == "active"
            and fav.get("registered") is True
            and not fav.get("error")
            and 0 <= now - checked <= MAX_AGE
            and 0 <= now - timestamp <= MAX_AGE
        )
    except (ValueError, TypeError):
        return False


def run_asterisk(action, target, timeout=15):
    Asterisk(ASTERISK, NODE).command(action, target, timeout=timeout)


def direct_links(timeout=8):
    return Asterisk(ASTERISK, NODE).links(timeout=timeout)


def scan(action, apply):
    with operation_lock(LOCK):
        return _scan(action, apply)


def _scan(action, apply):
    state = load_selection(STATE, NODE)
    previous = str(state.get('pending_node') or state.get('node') or '')
    if action == 'stop':
        if not apply:
            message = 'DRY RUN: Disconnect scanner-selected connection'
        else:
            message = perform('stop', None, LinkController(direct_links, run_asterisk), STATE, NODE)
        print(message)
        return message

    data = read_json(CACHE, {})
    samples = {str(f['node']): f for f in data.get('favorites', [])}
    favorites = [samples.get(f['node'], {}) | f for f in favorites_store.read()]

    if not favorites:
        raise RuntimeError("Activity cache has no favorites")

    now = int(time.time())

    if action == "first":
        start = 0
    else:
        old_index = next(
            (i for i, f in enumerate(favorites)
             if str(f["node"]) == previous),
            -1
        )
        start = (old_index + 1) % len(favorites)

    selected = None

    for offset in range(len(favorites)):
        index = (start + offset) % len(favorites)
        fav = favorites[index]

        if action == "next" and str(fav["node"]) == previous:
            continue

        if eligible(fav, now):
            selected = (index, fav)
            break

    if selected is None:
        print("No eligible active favorite found")
        print("Existing connection left unchanged")
        return

    index, fav = selected
    target = str(fav["node"])

    print(f"Selected: {target}")
    print(f"Name: {fav['name']}")
    print(f"Links: {fav.get('links', '-')}")
    print(f"Position: {index + 1} of {len(favorites)}")

    if not apply:
        print("DRY RUN: No connections changed")
        return

    message = perform('connect', target, LinkController(direct_links, run_asterisk), STATE, NODE)
    print(message)
    return message


def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["first", "next", "stop"])
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Submit actual Asterisk commands"
    )
    args = parser.parse_args()
    require_node()

    if args.apply:
        with command_guard(Path(CONFIG['paths']['runtime_dir'])/'web-control.lock',
                           STATE_DIR/'web-last-command.json', CONFIG['controls']['cooldown_seconds']):
            scan(args.action, True)
    else:
        scan(args.action, False)



def main():
    # Serialize trusted CLI/DTMF invocations with Admin node/cooldown changes too.
    from admin_settings import guard,refresh
    global NODE,MAX_AGE
    with guard():
        refresh(CONFIG)
        NODE=CONFIG['allstar']['local_node']
        MAX_AGE=CONFIG['monitor']['max_stats_age_seconds']
        _main()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        sys.exit(1)
