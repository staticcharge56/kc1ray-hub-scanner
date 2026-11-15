"""Fixed Phase 2 settings, timer schedules and safe diagnostic projections."""
import json
import math
from pathlib import Path
import re
import time
from security import Denied

PATHS={
    'local_node':('allstar','local_node'),
    'cooldown_seconds':('controls','cooldown_seconds'),
    'poll_interval_seconds':('monitor','poll_interval_seconds'),
    'max_stats_age_seconds':('monitor','max_stats_age_seconds'),
    'activity_window_seconds':('monitor','activity_window_seconds'),
}
# Web administration may slow polling, never exceed the existing default rate.
RANGES={'cooldown_seconds':(15,300),'poll_interval_seconds':(4,300),
        'max_stats_age_seconds':(60,3600),'activity_window_seconds':(60,3600),
        'netwatch_interval_minutes':(30,1440)}
SCHEDULE_FIELDS=('netwatch_interval_minutes','allstarnets_frequency')
CALENDARS={'daily':'*-*-* 03:00:00 UTC','weekly':'Sun *-*-* 03:00:00 UTC'}
DROPIN='50-hubscanner-admin.conf'
HEADER='# Managed by KC1RAY Hub Scanner Admin\n'


def validate(values,current):
    for key,value in values.items():
        if key in PATHS and value==current.get(key) and type(value) is type(current.get(key)):continue
        if key in RANGES:
            lo,hi=RANGES[key]
            if type(value) is not int or not lo<=value<=hi:
                raise Denied(400,f'{key} must be an integer from {lo} to {hi}')
        elif key=='local_node':
            if not isinstance(value,str) or not re.fullmatch(r'[0-9]{3,7}',value):raise Denied(400,'Invalid local node')
        elif key=='allstarnets_frequency' and (not isinstance(value,str) or value not in CALENDARS):
            raise Denied(400,'Choose daily or weekly AllStar Nets updates')


def timer_text(source,value):
    if source=='netwatch':return HEADER+f'[Timer]\nOnUnitActiveSec=\nOnBootSec=2min\nOnUnitActiveSec={value}min\n'
    return HEADER+'[Timer]\nOnCalendar=\nOnCalendar='+CALENDARS[value]+'\n'


def bounded_json(path):
    try:
        with Path(path).open('rb') as stream:raw=stream.read(1048577)
        if len(raw)>1048576:return None
        data=json.loads(raw)
        return data if isinstance(data,dict) else None
    except (OSError,ValueError,TypeError):return None


def number(value):
    try:return type(value) in (int,float) and math.isfinite(value) and value>=0
    except (ValueError,OverflowError):return False


def diagnostics(config,cache,now=None):
    """Never return raw strings from upstream errors, URLs, configuration or logs."""
    now=time.time() if now is None else now
    data=bounded_json(Path(cache)/'activity.json')
    if not data:return dict(state='unavailable',last_success=None,nodes=[],api=None,warnings=['Activity cache unavailable'])
    result=[];last=[]
    samples=data.get('favorites')
    if not isinstance(samples,list):return dict(state='unavailable',last_success=None,nodes=[],api=None,warnings=['Activity cache content is invalid'])
    for sample in samples[:100]:
        if not isinstance(sample,dict) or not isinstance(sample.get('node'),str) or not re.fullmatch(r'[0-9]{3,7}',sample['node']):continue
        checked=sample.get('checked');stamp=sample.get('stats_time')
        valid=number(checked) and number(stamp) and 0<stamp<=checked<=now
        if valid:last.append(checked)
        fresh=valid and now-checked<=config['monitor']['max_stats_age_seconds'] and now-stamp<=config['monitor']['max_stats_age_seconds']
        error=bool(sample.get('error'))
        result.append(dict(node=sample['node'],state='unknown' if error or not fresh else 'healthy',
                           freshness='fresh' if fresh else 'stale' if valid else 'unavailable',
                           last_success=checked if valid else None,api_error=error))
    def retry(value):
        if not isinstance(value,dict):return None
        # Existing retry snapshots store retry_at as a wall-clock timestamp.
        at=value.get('retry_at');failures=value.get('failures')
        return dict(retry_at=at if number(at) else None,active=number(at) and at>now,failures=failures if type(failures) is int and 0<=failures<=32 else None,error_kind=value.get('error_kind') if value.get('error_kind') in ('rate_limit','http','network','timeout','invalid_response','stale_response') else None)
    api=data.get('api');api=api if isinstance(api,dict) else {}
    nodes=api.get('nodes');nodes=nodes if isinstance(nodes,dict) else {}
    retries={node:retry(value) for node,value in list(nodes.items())[:100] if isinstance(node,str) and re.fullmatch(r'[0-9]{3,7}',node)}
    warnings=[]
    if samples and not result:warnings.append('No valid node samples in activity cache')
    if len(samples)>100:warnings.append('Node diagnostics limited to the first 100 favorites')
    if any(n['api_error'] for n in result):warnings.append('Statistics requests have failed; affected nodes remain unknown')
    if any(n['freshness']!='fresh' for n in result):warnings.append('Some statistics are stale or unavailable')
    count=len(samples);minimum=count*config['monitor']['poll_interval_seconds']
    if minimum>=min(config['monitor']['max_stats_age_seconds'],config['monitor']['activity_window_seconds']):warnings.append('Favorite polling cycle meets or exceeds a freshness window')
    updated=data.get('updated');cache_fresh=number(updated) and 0<updated<=now and now-updated<=config['monitor']['max_stats_age_seconds']
    return dict(state='healthy' if cache_fresh and (not samples or result) and all(n['state']=='healthy' for n in result) else 'stale' if not cache_fresh else 'degraded',
                last_success=max(last,default=None),nodes=result,api=dict(global_limit=retry(api),nodes=retries),
                minimum_cycle_seconds=minimum,warnings=warnings)


# Only known application-generated messages become summaries. Never show raw MESSAGE.
LOG_EVENTS=(('Activity cache write failed','Activity cache write failed'),
            ('Activity checkpoint failed','Activity history checkpoint failed'),
            ('Activity history unavailable;','Activity history unavailable; fresh baselines used'),
            ('Favorites reload failed','Favorites reload failed; previous favorites retained'),
            ('Statistics request failed for','Statistics request failed'),
            ('Polling ','Polling cycle freshness warning'),
            ('Net schedule update FAILED','AllStar Nets import failed; previous cache retained'),
            ('Administration startup/recovery failed','Admin startup or recovery failed'))


def safe_logs(raw):
    output=[]
    for line in raw.splitlines()[-100:]:
        try:
            item=json.loads(line);message=item.get('MESSAGE');stamp=item.get('__REALTIME_TIMESTAMP')
            if not isinstance(message,str):continue
            event=next((label for prefix,label in LOG_EVENTS if message.startswith(prefix)),None)
            if event is None:continue
            unit=item.get('_SYSTEMD_UNIT')
            if unit not in {f'kc1ray-hub-scanner-{s}.service' for s in ('web','broker','monitor','admin','netwatch','allstarnets')}:continue
            timestamp=int(stamp)/1000000 if isinstance(stamp,str) and stamp.isdecimal() and len(stamp)<=20 else None
            output.append(dict(unit=unit,time=timestamp,message=event))
        except (ValueError,TypeError,AttributeError):continue
    return output[-25:]
