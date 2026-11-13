"""Shared, read-only-at-runtime TOML configuration (Python 3.11+)."""
from copy import deepcopy
import os
import ipaddress
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit

DEFAULT_PATH = Path('/etc/kc1ray-hub-scanner/config.toml')
DEFAULTS = {
    'allstar': {'local_node': '', 'asterisk_binary': '/usr/sbin/asterisk'},
    'paths': {'state_dir': '/var/lib/kc1ray-hub-scanner',
              'cache_dir': '/var/cache/kc1ray-hub-scanner',
              'runtime_dir': '/run/kc1ray-hub-scanner',
              'monitor_state_dir': '',
              'scanner_script': str(Path(__file__).resolve().parent / 'scanner.py')},
    'web': {'allow_lan_http': False, 'bind': '127.0.0.1', 'port': 8085, 'controls_enabled': False,
            'refresh_seconds': 10, 'anonymous_view': False, 'allowed_origins': [],
            'trusted_proxies': [], 'request_timeout_seconds': 5, 'max_workers': 16},
    'auth': {'credentials_file': '/etc/kc1ray-hub-scanner/credentials.json',
             'session_idle_seconds': 1800, 'session_max_seconds': 28800,
             'max_sessions': 128, 'login_attempts': 5, 'login_global_attempts': 20,
             'login_window_seconds': 300, 'sensitive_attempts': 30,
             'sensitive_window_seconds': 60, 'read_attempts': 180, 'read_window_seconds': 60},
    'broker': {'socket_path': '/run/kc1ray-hub-scanner/control.sock',
               'web_uid': -1, 'service_uid': -1, 'socket_gid': -1,
               'timeout_seconds': 30, 'max_workers': 8},
    'monitor': {'poll_interval_seconds': 4, 'max_stats_age_seconds': 300,
                'activity_window_seconds': 300, 'request_timeout_seconds': 10,
                'history_retention_seconds': 86400, 'history_write_interval_seconds': 60,
                'cache_write_interval_seconds': 15, 'response_max_bytes': 262144,
                'backoff_initial_seconds': 30, 'backoff_max_seconds': 900,
                'stats_url_template': 'https://stats.allstarlink.org/api/stats/{node}'},
    'controls': {'cooldown_seconds': 15},
    'schedules': {
        'netwatch': {'enabled': False, 'url': 'https://newenglanddigitalradio.com/netwatch/api.php',
                     'details_url': 'https://newenglanddigitalradio.com/netwatch/',
                     'max_age_seconds': 5400, 'request_timeout_seconds': 20},
        'allstarnets': {'enabled': False, 'url': 'https://allstarnets.org/',
                        'details_url': 'https://allstarnets.org/', 'max_age_seconds': 259200,
                        'request_timeout_seconds': 25, 'estimated_duration_minutes': 60}}}


def _merge(base, supplied, prefix=''):
    if not isinstance(supplied, dict):
        raise ValueError(f'{prefix or "configuration"} must be a table')
    for key, value in supplied.items():
        name = prefix + key
        if key not in base:
            raise ValueError(f'Unknown configuration key: {name}')
        if isinstance(base[key], dict):
            _merge(base[key], value, name + '.')
        else:
            if type(value) is not type(base[key]):
                raise ValueError(f'Invalid type for {name}')
            base[key] = value


def load_config(path=None):
    """Never create or rewrite configuration; an explicit missing file is an error."""
    selected = path if path is not None else os.environ.get('KC1RAY_CONFIG')
    target = Path(selected) if selected is not None else DEFAULT_PATH
    data = deepcopy(DEFAULTS)
    if selected is not None or target.exists():
        with target.open('rb') as stream:
            _merge(data, tomllib.load(stream))
    node = data['allstar']['local_node']
    if node and not re.fullmatch(r'[0-9]{3,7}', node):
        raise ValueError('allstar.local_node must contain 3–7 ASCII digits')
    # Preserve existing layouts; packaging can give the unprivileged monitor its own state.
    if not data['paths']['monitor_state_dir']:
        data['paths']['monitor_state_dir'] = data['paths']['state_dir']
    for name, value in data['paths'].items():
        if not Path(value).is_absolute() or '\x00' in value:
            raise ValueError(f'paths.{name} must be an absolute path')
    for section, key in (('auth', 'credentials_file'), ('broker', 'socket_path')):
        value = data[section][key]
        if not Path(value).is_absolute() or '\x00' in value:
            raise ValueError(f'{section}.{key} must be absolute')
    if not Path(data['allstar']['asterisk_binary']).is_absolute() or '\x00' in data['allstar']['asterisk_binary']:
        raise ValueError('allstar.asterisk_binary must be absolute')
    bind = data['web']['bind']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', bind):
        raise ValueError('web.bind must be an IPv4 address or host name (IPv6 is not supported yet)')
    if re.fullmatch(r'[0-9.]+', bind):
        ipaddress.IPv4Address(bind)
    if data['web']['allow_lan_http']:
        address=ipaddress.IPv4Address(bind)
        if not any(address in ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
            raise ValueError('web.allow_lan_http requires a specific RFC1918 LAN IPv4 bind')
        if f'http://{bind}:{data["web"]["port"]}' not in data['web']['allowed_origins']:
            raise ValueError('web.allow_lan_http requires its exact HTTP origin')
    if not 1 <= data['web']['port'] <= 65535:
        raise ValueError('web.port must be 1–65535')
    for section in ('monitor', 'controls', 'web', 'auth', 'broker'):
        for name, value in data[section].items():
            if name.endswith('_seconds') and value <= 0:
                raise ValueError(f'{section}.{name} must be positive')
    for section, keys in (('web', ('max_workers',)), ('broker', ('max_workers',)),
                          ('auth', ('max_sessions', 'login_attempts', 'login_global_attempts',
                                    'sensitive_attempts', 'read_attempts'))):
        for key in keys:
            if not 1 <= data[section][key] <= 4096:
                raise ValueError(f'{section}.{key} must be 1–4096')
    if data['auth']['session_max_seconds'] < data['auth']['session_idle_seconds']:
        raise ValueError('Maximum session lifetime must be >= idle timeout')
    for key in ('web_uid', 'service_uid', 'socket_gid'):
        if data['broker'][key] < -1:
            raise ValueError(f'broker.{key} must be -1 (unconfigured) or nonnegative')
    for key in ('allowed_origins', 'trusted_proxies'):
        if any(not isinstance(value, str) for value in data['web'][key]):
            raise ValueError(f'web.{key} must contain strings')
    for network in data['web']['trusted_proxies']:
        ipaddress.ip_network(network, strict=True)
    for origin in data['web']['allowed_origins']:
        parts = urlsplit(origin)
        if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.path or
                parts.query or parts.fragment or parts.username or parts.password or
                any(c.isspace() or ord(c) < 32 for c in origin)):
            raise ValueError('allowed_origins entries must be exact http(s) origins without paths')
        parts.port
    if not 1024 <= data['monitor']['response_max_bytes'] <= 16 * 1024 * 1024:
        raise ValueError('monitor.response_max_bytes must be 1024–16777216')
    if data['monitor']['backoff_max_seconds'] < data['monitor']['backoff_initial_seconds']:
        raise ValueError('monitor.backoff_max_seconds must be >= backoff_initial_seconds')
    for section, source in data['schedules'].items():
        for name, value in source.items():
            if (name.endswith('_seconds') or name.endswith('_minutes')) and value <= 0:
                raise ValueError(f'schedules.{section}.{name} must be positive')
    if data['schedules']['allstarnets']['estimated_duration_minutes'] > 240:
        raise ValueError('estimated_duration_minutes must be at most 240')
    for source in data['schedules'].values():
        details = urlsplit(source['details_url'])
        if not details.path.endswith('/') or details.query:
            raise ValueError('details_url must end in / and have no query')
    template = data['monitor']['stats_url_template']
    if template.count('{node}') != 1 or '{' in template.replace('{node}', '') or '}' in template.replace('{node}', ''):
        raise ValueError('stats_url_template must contain exactly one {node}')
    urls = [template.replace('{node}', '1000')]
    urls += [s[k] for s in data['schedules'].values() for k in ('url', 'details_url')]
    for url in urls:
        if any(c.isspace() or ord(c) < 32 for c in url):
            raise ValueError('External URLs cannot contain whitespace/control characters')
        parts = urlsplit(url)
        if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValueError('External URLs must use HTTPS without credentials or fragments')
        try:
            parts.port
        except ValueError as exc:
            raise ValueError('Invalid URL port') from exc
    return data


CONFIG = load_config()


def require_node():
    if not CONFIG['allstar']['local_node']:
        raise ValueError('Set allstar.local_node in TOML (KC1RAY_CONFIG or ' + str(DEFAULT_PATH) + ')')
