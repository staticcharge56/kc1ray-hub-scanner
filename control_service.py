"""Narrow command policy around the existing Asterisk/scanner implementation."""
import threading
import time
import re
from security import Denied
from radio_control import command_guard, Busy, RadioError, RadioTimeout, load_selection, normalize_links

ACTIONS={'first','next','stop','connect-node','disconnect-node','connect-net','disconnect-net'}


def selected_node(driver):
    try:
        state = load_selection(driver.SCANNER_STATE, driver.LOCAL_NODE)
        return state.get('pending_node') or state.get('node') or None
    except RadioError:
        raise Denied(503, 'Invalid scanner state') from None


def validate_control(payload,driver):
    if not isinstance(payload,dict) or not set(payload)<= {'action','node'} or not isinstance(payload.get('action'),str) or payload.get('action') not in ACTIONS:
        raise Denied(400,'Invalid control request')
    action,node=payload['action'],payload.get('node')
    if action in ('first','next','stop'):
        if node is not None:
            raise Denied(400,'Unexpected destination')
        if action=='stop':
            selected_node(driver)
        return action,None
    pattern=r'[0-9]{3,7}' if action.endswith('-net') else r'[0-9]{4,7}'
    if not isinstance(node,str) or not re.fullmatch(pattern,node) or node==driver.LOCAL_NODE:
        raise Denied(400,'Invalid destination')
    if action.endswith('-node'):
        allowed=driver.favorite_numbers()
    elif action=='connect-net':
        allowed=driver.scheduled_net_numbers()
    else:
        allowed=driver.favorite_numbers() | driver.scheduled_net_numbers()
        selected=selected_node(driver)
        if selected is not None:
            allowed.add(selected)
    if node not in allowed:
        raise Denied(403,'Destination is not authorized')
    return action,node


class ControlService:
    def __init__(self,driver):
        self.driver=driver
        self.link_lock=threading.Lock()
        self.cached_links=None
        self.links_checked=None

    def links(self):
        if not self.link_lock.acquire(blocking=False):
            raise Denied(429,'Link status busy',1)
        try:
            now=time.monotonic()
            if self.links_checked is None or now-self.links_checked>=5:
                self.links_checked=now
                self.cached_links=None
                self.cached_links=self.driver.direct_links()
            if self.cached_links is None:
                raise Denied(503,'Link status unavailable')
            records=normalize_links(self.cached_links)
            return {'links':[record['node'] for record in records], 'link_states':records}
        finally:
            self.link_lock.release()

    def control(self,payload):
        driver=self.driver
        if not driver.CONFIG['web']['controls_enabled']:
            raise Denied(403,'Mutations disabled by configuration')
        # Authorization precedes any reservation or state-changing operation.
        action,node=validate_control(payload,driver)
        try:
            with command_guard(driver.LOCK, driver.LAST_COMMAND, driver.COOLDOWN_SECONDS):
                try:
                    if action in ('first','next','stop'):
                        message=driver.scan_action(action)
                    else:
                        message=driver.run_link_action(action,node)
                    return {'message':message or 'No eligible active favorite found; existing connection unchanged'}
                finally:
                    # A failed transition may have already disconnected old links.
                    self.cached_links=None
                    self.links_checked=None
        except Busy as exc:
            raise Denied(429,str(exc),exc.retry_after) from None
        except RadioTimeout:
            raise Denied(504,'Radio transition timed out; check reported link status') from None
        except (RadioError,RuntimeError,OSError,ValueError,TypeError,KeyError):
            raise Denied(503,'Radio transition failed; check reported link status') from None
