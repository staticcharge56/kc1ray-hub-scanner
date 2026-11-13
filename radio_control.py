"""Application-owned, bounded Asterisk link transitions. Never edits ASL settings."""
from contextlib import contextmanager
import fcntl
import json
import math
from pathlib import Path
import re
import subprocess
import time

from activity_history import atomic_json

TRANSITION_SECONDS = 18
CALL_SECONDS = 3
POLL_SECONDS = .5


class RadioError(RuntimeError):
    pass


class RadioTimeout(RadioError):
    pass


class Busy(RadioError):
    def __init__(self, message, retry_after=1):
        super().__init__(message)
        self.retry_after = retry_after


def node_number(node, local=None):
    if not isinstance(node, str) or not re.fullmatch(r'[0-9]{3,7}', node) or node == local:
        raise RadioError('Invalid radio destination')
    return node


def link_record(node, suffix=None):
    """Verified RPT_ALINKS modes: T/R established, C connecting; K/U keyed."""
    node_number(node)
    if suffix is not None and (not isinstance(suffix, str) or not re.fullmatch(r'[A-Za-z]{2}', suffix)):
        raise RadioError('Invalid Asterisk link metadata')
    mode = suffix[0] if suffix else None
    keyed = {'K':True, 'U':False}.get(suffix[1]) if suffix else None
    state = 'unknown'
    if keyed is not None:
        if mode in ('T', 'R'):
            state = 'established'
        elif mode == 'C':
            state = 'connecting'
    return {'node':node, 'mode':mode, 'keyed':keyed, 'state':state, 'suffix':suffix}


def normalize_links(links):
    """Keep unknown metadata unknown; never upgrade bare IDs into established."""
    if not isinstance(links, list) or len(links) > 256:
        raise RadioError('Invalid Asterisk link snapshot')
    records = []
    seen = set()
    for entry in links:
        if isinstance(entry, str):
            record = link_record(entry) # Legacy/custom callers: unverified.
        elif isinstance(entry, dict):
            record = link_record(entry.get('node'), entry.get('suffix'))
            if entry != record or type(entry.get('keyed')) is not type(record['keyed']):
                raise RadioError('Inconsistent Asterisk link metadata')
        else:
            raise RadioError('Invalid Asterisk link record')
        if record['node'] in seen:
            raise RadioError('Duplicate Asterisk link record')
        seen.add(record['node'])
        records.append(record)
    return records


def parse_links(output):
    """Reject incomplete/ambiguous status instead of interpreting it as empty."""
    if not isinstance(output, str) or len(output) > 65536:
        raise RadioError('Invalid Asterisk link status')
    # Count field candidates before accepting an empty value: a valid line plus
    # a malformed duplicate must not be mistaken for an unconnected node.
    lines = [line for line in output.split('\n')
             if re.match(r'^\s*RPT_ALINKS\b', line, re.I)]
    if len(lines) != 1:
        raise RadioError('Asterisk link status unavailable')
    field = re.fullmatch(r'[ \t]*RPT_ALINKS=([^\r\n]*)\r?', lines[0])
    if not field:
        raise RadioError('Malformed Asterisk link status')
    # ASL3 emits an empty string, not necessarily "0", with no adjacent links.
    # Require a literally empty value; whitespace-only/partial values fail below.
    value = field[1]
    if value == '':
        return []
    items = value.strip().split(',')
    if not re.fullmatch(r'[0-9]{1,3}', items[0]) or int(items[0]) > 256:
        raise RadioError('Invalid Asterisk link count')
    links = []
    seen = set()
    for item in items[1:]:
        match = re.fullmatch(r'([0-9]{3,7})([A-Za-z]{2})', item.strip())
        if not match or match[1] in seen:
            raise RadioError('Ambiguous Asterisk link status')
        seen.add(match[1])
        links.append(link_record(match[1], match[2]))
    if len(links) != int(items[0]):
        raise RadioError('Incomplete Asterisk link status')
    return links


class Asterisk:
    def __init__(self, binary, local):
        self.binary = binary
        self.local = node_number(local)

    def run(self, command, timeout):
        try:
            result = subprocess.run([self.binary, '-rx', command], capture_output=True,
                                    text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RadioTimeout('Asterisk request timed out; check reported links') from None
        except OSError:
            raise RadioError('Asterisk request unavailable') from None
        if result.returncode or 'No such command' in result.stdout:
            raise RadioError('Asterisk request failed; check reported links')
        return result.stdout

    def links(self, timeout=8):
        return parse_links(self.run(f'rpt show variables {self.local}', timeout))

    def command(self, action, target, timeout=15):
        node_number(target, self.local)
        if action not in ('connect', 'disconnect'):
            raise RadioError('Invalid radio action')
        index = '3' if action == 'connect' else '1'
        self.run(f'rpt cmd {self.local} ilink {index} {target}', timeout)


@contextmanager
def operation_lock(path):
    with Path(path).open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy('Scanner is busy') from None
        yield


@contextmanager
def command_guard(lock_path, cooldown_path, seconds):
    """Same file/15s policy for broker and trusted local CLI, including failures."""
    with operation_lock(lock_path):
        try:
            last = json.loads(Path(cooldown_path).read_text())['time']
            if (type(last) not in (int, float) or not math.isfinite(last) or
                    last < 0 or last > time.time()+86400):
                raise ValueError()
        except FileNotFoundError:
            last = 0
        except (ValueError, TypeError, KeyError, OverflowError):
            raise RadioError('Control cooldown state unavailable') from None
        wait = seconds-(time.time()-last)
        if wait > 0:
            raise Busy('Radio command cooldown', max(1, math.ceil(wait)))
        atomic_json(Path(cooldown_path), {'time':time.time()})
        try:
            yield
        finally:
            atomic_json(Path(cooldown_path), {'time':time.time()})


class LinkController:
    def __init__(self, query, command, observer=None):
        self.query, self.command = query, command
        self.deadline = time.monotonic()+TRANSITION_SECONDS
        self.state = 'unknown'
        self.observer = observer

    def set_state(self, state):
        self.state = state
        if self.observer:
            self.observer(state)

    def remaining(self):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            raise RadioTimeout('Link transition timed out; check reported links')
        return min(CALL_SECONDS, remaining)

    def links(self):
        records = normalize_links(self.query(timeout=self.remaining()))
        # A late response cannot extend the operation's monotonic deadline.
        self.remaining()
        return {record['node']:record for record in records}

    def verified(self):
        current = self.links()
        if any(record['state'] == 'unknown' for record in current.values()):
            self.set_state('unknown')
            raise RadioError('Unverified Asterisk link state; operation aborted')
        return current

    def issue(self, action, node):
        self.command(action, node, timeout=self.remaining())

    def pause(self):
        time.sleep(min(POLL_SECONDS, self.remaining()))

    def await_established(self, target, observed=False):
        self.set_state('connecting')
        while True:
            current = self.verified()
            if set(current)-{target}:
                raise RadioError('Unexpected connection during connect; check reported links')
            record = current.get(target)
            if record:
                observed = True
                if record['state'] == 'established':
                    self.set_state('established')
                    return
            elif observed:
                self.set_state('disconnected')
                raise RadioError('Connection disappeared before establishment')
            self.pause()

    def connect(self, target, pending):
        try:
            return self._connect(target, pending)
        except RadioError:
            if self.state != 'disconnected':
                self.set_state('unknown')
            raise

    def _connect(self, target, pending):
        node_number(target)
        links = self.verified()
        if set(links) == {target}:
            if links[target]['state'] == 'established':
                self.set_state('established')
                return False
            # Already-only C: do not tear down/reissue; wait and never confirm C.
            pending(target)
            self.await_established(target, observed=True)
            return False
        old = set(links)
        if old:
            self.set_state('disconnecting') # Application intent, NOT a wire suffix.
        for node in sorted(old):
            self.issue('disconnect', node)
        if old:
            while True:
                current = self.verified()
                if set(current)-old:
                    raise RadioError('Connections changed during disconnection; new connect aborted')
                if not current:
                    break
                self.pause()
        if self.verified():
            raise RadioError('Connections changed before connect; new connect aborted')
        self.set_state('disconnected')
        pending(target)
        self.set_state('connecting')
        self.issue('connect', target)
        self.await_established(target)
        return True

    def disconnect(self, target):
        try:
            node_number(target)
            if target not in self.verified():
                self.set_state('disconnected')
                return False
            self.set_state('disconnecting')
            self.issue('disconnect', target)
            # T, R and C entries are all present. Only absence confirms removal.
            while target in self.verified():
                self.pause()
            self.set_state('disconnected')
            return True
        except RadioError:
            self.set_state('unknown')
            raise


def load_selection(path, local):
    try:
        state = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise RadioError('Scanner selection state unavailable') from None
    if not isinstance(state, dict):
        raise RadioError('Invalid scanner selection state')
    for key in ('node', 'pending_node'):
        value = state.get(key)
        if value not in (None, ''):
            node_number(value, local)
    return state


def perform(action, target, controller, path, local):
    """Caller holds scanner.lock through query, commands, confirmation and state."""
    state = load_selection(path, local)
    if 'confirmed' in state:
        state = state | {'confirmed':False}
        atomic_json(Path(path), state)
    if action == 'stop':
        selected = [state.get('pending_node'), state.get('node')]
        candidates = [node for node in selected if node]
        if not candidates:
            return 'No scanner-selected connection to stop'
        active = controller.links()
        target = next((node for node in candidates if node in active), None)
        if target is None:
            atomic_json(Path(path), {})
            return 'No scanner-selected connection is active; selection cleared'
        action = 'disconnect'
    node_number(target, local)
    if action == 'connect':
        def pending(node):
            atomic_json(Path(path), state | {'pending_node':node, 'confirmed':False})
        changed = controller.connect(target, pending)
        atomic_json(Path(path), {'node':target, 'selected_at':int(time.time()), 'confirmed':True})
        return ('Connected to node '+target+'; reported link confirmed' if changed else
                'Node '+target+' is already the only connection; no command issued')
    if action != 'disconnect':
        raise RadioError('Invalid radio action')
    changed = controller.disconnect(target)
    if state.get('node') == target:
        state.pop('node', None)
        state.pop('selected_at', None)
        state.pop('confirmed', None)
    if state.get('pending_node') == target:
        state.pop('pending_node', None)
    if not state.get('node') and not state.get('pending_node'):
        state = {}
    atomic_json(Path(path), state)
    return ('Disconnected node '+target+'; reported removal confirmed' if changed else
            'Node '+target+' is not directly connected; nothing changed')
