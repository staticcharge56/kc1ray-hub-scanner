#!/usr/bin/env python3
"""KC1RAY Hub Scanner dashboard and legacy radio controls."""

import favorites_store
from radio_control import Asterisk, LinkController, operation_lock, perform
import json
import logging
import re
import time
import secrets
import threading
import socket
from broker import rpc, validate_web_identity
from security import (Security, Credentials, Denied, request_context, cookie_token, session_cookie)
from web_auth import LOGIN_HTML, APP_AUTH
from urllib.parse import urlsplit
from configuration import CONFIG, require_node
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CACHE = Path(CONFIG['paths']['cache_dir']) / 'activity.json'
NETS_CACHE = Path(CONFIG['paths']['cache_dir']) / 'nets.json'
NETWATCH_CACHE = Path(CONFIG['paths']['cache_dir']) / 'netwatch-nets.json'
NETWATCH_MAX_AGE_SECONDS = CONFIG['schedules']['netwatch']['max_age_seconds']
NET_DURATION_MINUTES = CONFIG['schedules']['allstarnets']['estimated_duration_minutes']
NET_CACHE_MAX_AGE_SECONDS = CONFIG['schedules']['allstarnets']['max_age_seconds']
SCANNER = Path(CONFIG['paths']['scanner_script'])
STATE_DIR = Path(CONFIG['paths']['state_dir'])
SCANNER_STATE = STATE_DIR / 'scanner-state.json'
SCANNER_LOCK = Path(CONFIG['paths']['runtime_dir']) / 'scanner.lock'
ASTERISK = CONFIG['allstar']['asterisk_binary']
LOCAL_NODE = CONFIG['allstar']['local_node']
LOCK = Path(CONFIG['paths']['runtime_dir']) / 'web-control.lock'
LAST_COMMAND = STATE_DIR / 'web-last-command.json'
HOST = CONFIG['web']['bind']
PORT = CONFIG['web']['port']
COOLDOWN_SECONDS = CONFIG['controls']['cooldown_seconds']

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KC1RAY Hub Scanner</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #101720; color: #f1f5f9; }
body { margin: 0; padding: 16px; }
main { max-width: 650px; margin: auto; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.05rem; margin: 0 0 12px; }
small, .muted { color: #9ca3af; }
.summary { display: flex; gap: 10px; margin: 18px 0; }
.summary div { background: #1e293b; flex: 1; text-align: center; border-radius: 10px; padding: 12px 6px; }
.summary strong { display: block; font-size: 1.5rem; }
.panel { background: #1e293b; border-radius: 12px; padding: 14px; margin: 16px 0; }
.radio-buttons { display: grid; grid-template-columns: repeat(3,1fr); gap: 8px; }
button { border: 0; border-radius: 8px; padding: 12px; background: #334155; color: #fff; font-size: 1rem; cursor: pointer; }
.radio-buttons button { min-height: 68px; font-weight: bold; background: #2563eb; }
.radio-buttons button.stop { background: #991b1b; }
button:disabled { opacity: .55; cursor: not-allowed; }
button.selected { background: #2563eb; }
#control-status { color: #cbd5e1; font-size: .9rem; white-space: pre-line; overflow-wrap: anywhere; margin-bottom: 0; }
.controls { display: flex; gap: 8px; margin: 14px 0; }
.node { background: #1e293b; border-radius: 10px; margin-bottom: 8px; padding: 14px; display: flex; align-items: center; gap: 12px; }
.dot { height: 13px; width: 13px; border-radius: 50%; flex-shrink: 0; }
.active { background: #22c55e; }
.idle { background: #64748b; }
.unknown { background: #f59e0b; }
 .details { flex: 1; min-width: 0; }
.net-tag { display: inline-block; margin-top: 5px; padding: 3px 7px; border-radius: 6px; font-size: .78rem; font-weight: 700; background: #475569; color: #fff; }
.net-tag.onair { background: #166534; }
.net-tag.scheduled { background: #92400e; }
.net-name { font-size: .79rem; margin-top: 4px; color: #cbd5e1; overflow-wrap: anywhere; }
.net-name a { color: #93c5fd; }
#schedule-status { font-size: .79rem; color: #9ca3af; margin-bottom: 8px; }
.name { font-weight: 600; overflow-wrap: anywhere; }
.meta { font-size: .85rem; color: #9ca3af; margin-top: 4px; }
 .links { white-space: nowrap; color: #cbd5e1; font-size: .85rem; }
.node-right { display: flex; flex-direction: column; align-items: end; gap: 8px; }
.node-button { min-height: 42px; min-width: 108px; padding: 9px 11px; background: #2563eb; font-size: .9rem; font-weight: 650; }
.node-button.disconnect { background: #991b1b; }
.node-button:disabled { opacity: .5; }
.net-actions { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
.net-actions button { font-size: .85rem; font-weight: 600; padding: 9px 11px; }
.net-action-connect { background: #2563eb; }
.net-action-connect.disconnect { background: #991b1b; }
.net-action-favorite { background: #475569; }
#link-status { color: #cbd5e1; font-size: .83rem; margin: 0 0 10px; }
@media(max-width:420px){ .node { gap:8px; padding:11px; } .node-button { min-width:94px; } }

#message { font-size: .85rem; color: #cbd5e1; }
.screen-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 12px 0; }
#wakeButton { background: #2563eb; font-weight: 600; }
#wakeButton.selected { background: #166534; }
#wakeStatus { font-size: .82rem; color: #cbd5e1; flex: 1; min-width: 180px; }
</style>
</head>
<body>
<main>
<h1>KC1RAY Hub Scanner</h1>
<p><span id="account-status">Checking session…</span> · <a id="signin" href="/login">Sign in</a> <button id="logout" hidden>Sign out</button></p>
<small>AllStarLink Node __LOCAL_NODE__</small>
<div class="summary">
  <div><strong id="activeCount">-</strong>Active</div>
  <div><strong id="idleCount">-</strong>Idle</div>
  <div><strong id="totalCount">-</strong>Favorites</div>
</div>
<section class="panel">
  <h2>Hub Controls</h2>
  <div class="radio-buttons">
    <button type="button" data-action="first">&#9654; FIRST</button>
    <button type="button" data-action="next">&#9197; NEXT</button>
    <button type="button" class="stop" data-action="stop">&#9632; STOP</button>
  </div>
  <p id="control-status" role="status" aria-live="polite">Ready — Node __LOCAL_NODE__</p>
  <div class="screen-controls">
    <button type="button" id="wakeButton" data-action="wake">Keep Screen Awake: OFF</button>
    <span id="wakeStatus" role="status" aria-live="polite">Optional screen wake lock for mobile devices.</span>
  </div>
</section>
<div class="controls">
  <button id="activeBtn" class="selected" data-action="filter-active">Active</button>
  <button id="allBtn" data-action="filter-all">All</button>
</div>
<p id="message">Loading cached statistics...</p>
<p id="link-status">Checking direct connections...</p>
<p id="schedule-status">Checking saved net schedule...</p>
<div id="nodes"></div>
</main>
<script>
const publicConfig = __PUBLIC_CONFIG__;
__APP_AUTH__
let filter = 'active';
let favorites = [];
let cacheUpdated = 0;
let netSchedule = {updated: 0, nets: [], default_duration_minutes: publicConfig.netDuration};
let commandBusy = false;
let directLinks = [];
let directLinkStates = new Map();
let linksKnown = false;
let wakeLock = null;
let wakeRequested = false;

function wakeStatus(message) {
  document.getElementById('wakeStatus').textContent = message;
  const button = document.getElementById('wakeButton');
  button.textContent = 'Keep Screen Awake: ' + (wakeLock ? 'ON' : 'OFF');
  button.classList.toggle('selected', !!wakeLock);
}

async function acquireWakeLock() {
  if (!wakeRequested || document.visibilityState !== 'visible') return;
  if (!window.isSecureContext || !('wakeLock' in navigator)) {
    wakeRequested = false;
    wakeStatus('Requires HTTPS and a browser supporting Screen Wake Lock. Current HTTP address cannot prevent screen sleep.');
    return;
  }
  try {
    if (wakeLock) return;
    const sentinel = await navigator.wakeLock.request('screen');
    wakeLock = sentinel;
    sentinel.addEventListener('release', () => {
      if (wakeLock === sentinel) wakeLock = null;
      wakeStatus(wakeRequested ? 'Screen wake lock released; will retry when tab is visible.' : 'Screen sleep allowed.');
    });
    wakeStatus('Screen will stay awake while this tab is visible.');
  } catch (error) {
    wakeStatus('Wake lock unavailable: ' + error.message);
  }
}

async function toggleWakeLock() {
  if (wakeRequested) {
    wakeRequested = false;
    const previous = wakeLock;
    wakeLock = null;
    if (previous) await previous.release();
    wakeStatus('Screen sleep allowed.');
  } else {
    wakeRequested = true;
    await acquireWakeLock();
  }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && wakeRequested && !wakeLock) {
    acquireWakeLock();
  }
});

function setFilter(value) {
  filter = value;
  document.getElementById('activeBtn').classList.toggle('selected', value === 'active');
  document.getElementById('allBtn').classList.toggle('selected', value === 'all');
  render();
}

// NetWatch supplies absolute UTC start/end times; fallback accepts weekly UTC events.
function netOccurrences(net, referenceMs) {
  if (net.start && net.end) {
    const begin = Date.parse(net.start);
    const end = Date.parse(net.end);
    return Number.isFinite(begin) && Number.isFinite(end) && end > begin
      ? [{start: begin, end}] : [];
  }
  const bits = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(String(net.start_utc || ''));
  const day = Number(net.weekday);
  if (!bits || !Number.isInteger(day) || day < 0 || day > 6) return [];
  const d = new Date(referenceMs);
  const monday = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - ((d.getUTCDay()+6)%7));
  const offset = (day*86400 + Number(bits[1])*3600 + Number(bits[2])*60)*1000;
  const duration = Math.min(240, Math.max(1, Number(netSchedule.default_duration_minutes)||publicConfig.netDuration))*60000;
  return [-1,0,1,2].map(w => ({start:monday+w*7*86400000+offset, end:monday+w*7*86400000+offset+duration}));
}

function netForNode(node, nowSeconds) {
  const age = nowSeconds - Number(netSchedule.updated || 0);
  const maxAge = netSchedule.source === 'NetWatch' ? publicConfig.netwatchMaxAge : publicConfig.netsMaxAge;
  if (age < 0 || age > maxAge) return {current:null, upcoming:null};
  let current = null, upcoming = null;
  const nowMs = nowSeconds * 1000;
  for (const net of netSchedule.nets || []) {
    if (String(net.node) !== String(node)) continue;
    for (const t of netOccurrences(net, nowMs)) {
      const occurrence = {...net, startMs:t.start, endMs:t.end};
      if (t.start <= nowMs && nowMs < t.end) {
        if (!current || t.start > current.startMs) current=occurrence;
      } else if (t.start > nowMs && t.start <= nowMs + 86400000) {
        if (!upcoming || t.start < upcoming.startMs) upcoming=occurrence;
      }
    }
  }
  return {current, upcoming};
}

let nodeDescriptions = Object.create(null);
function rememberNodeDescriptions(data) {
  // Reuse the local activity cache; a failed refresh leaves prior metadata intact.
  if (!(Number(data.updated)>0) || !Array.isArray(data.favorites)) return;
  const descriptions=Object.create(null);
  for (const f of data.favorites) {
    if (typeof f.node_description==='string' && f.node_description.trim()) {
      descriptions[String(f.node)]=f.node_description.trim();
    }
  }
  nodeDescriptions=descriptions;
  document.dispatchEvent(new Event('node-descriptions-updated'));
}
function nodeInfoLine(node, status='') {
  const description=nodeDescriptions[String(node)];
  const labels={active:'Active',idle:'Idle',unknown:'Unknown'};
  return ['Node '+node,description,labels[status] || status].filter(Boolean).join(' - ');
}

function render() {
  const now = Date.now() / 1000;
  const age = Math.max(0, Math.floor(now - cacheUpdated));
  const effective = favorites.map(f => {
    const checkedAge = now - (f.checked || 0);
    const statsAge = now - (f.stats_time || 0);
    const fresh = checkedAge >= 0 && checkedAge <= publicConfig.statsMaxAge &&
                  statsAge >= 0 && statsAge <= publicConfig.statsMaxAge && !f.error;
    const displayStatus = fresh ? f.activity : 'unknown';
    const nets = netForNode(f.node, now);
    return {...f, displayStatus, currentNet: nets.current, upcomingNet: nets.upcoming,
      activeNet: displayStatus === 'active' && !!nets.current};
  });

  document.getElementById('activeCount').textContent =
    effective.filter(f => f.displayStatus === 'active').length;
  document.getElementById('idleCount').textContent =
    effective.filter(f => f.displayStatus === 'idle').length;
  document.getElementById('totalCount').textContent = favorites.length;
  document.getElementById('message').textContent =
    cacheUpdated ? 'Cache updated ' + age + ' seconds ago' : 'Waiting for activity cache';

  const root = document.getElementById('nodes');
  root.replaceChildren();
  const priority = f => f.activeNet ? 0 : f.displayStatus === 'active' ? 1 : f.currentNet ? 2 : f.displayStatus === 'idle' ? 3 : 4;
  const visible = effective.filter(f => filter === 'all' || f.displayStatus === 'active')
    .sort((a,b) => priority(a) - priority(b));
  if (!visible.length) {
    const p = document.createElement('p');
    p.textContent = filter === 'active' ? 'No active favorites in the current cache.' : 'No favorites available.';
    root.appendChild(p);
  }
  for (const f of visible) {
    const row = document.createElement('div');
    row.className = 'node';
    const dot = document.createElement('span');
    dot.className = 'dot ' + (['active', 'idle'].includes(f.displayStatus) ? f.displayStatus : 'unknown');
    const details = document.createElement('div');
    details.className = 'details';
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = f.name;
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = nodeInfoLine(f.node, f.displayStatus);
    details.append(name, meta);
    if (f.currentNet) {
      const tag = document.createElement('span');
      tag.className = 'net-tag ' + (f.activeNet ? 'onair' : 'scheduled');
      tag.textContent = f.activeNet ? 'Active Net' : 'Scheduled Net';
      const netName = document.createElement('div');
      netName.className = 'net-name';
      netName.textContent = f.currentNet.name + ' · ' +
        (f.currentNet.startMs ? new Date(f.currentNet.startMs).toLocaleTimeString([], {hour:'numeric', minute:'2-digit', timeZoneName:'short'}) : f.currentNet.start_utc+' UTC');
      details.append(tag, netName);
    } else if (f.upcomingNet) {
      const tag = document.createElement('span');
      tag.className = 'net-tag scheduled';
      tag.textContent = 'Upcoming Net';
      const info = document.createElement('div');
      info.className = 'net-name';
      info.textContent = f.upcomingNet.name + ' · ' +
        new Date(f.upcomingNet.startMs).toLocaleString([], {weekday:'short',hour:'numeric',minute:'2-digit',timeZoneName:'short'});
      details.append(tag, info);
    }
    const right = document.createElement('div');
    right.className = 'node-right';
    const links = document.createElement('div');
    links.className = 'links';
    links.textContent = (f.links ?? '-') + ' links';
    const connected = directLinks.includes(String(f.node));
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'node-button' + (connected ? ' disconnect' : '');
    button.textContent = connected ? disconnectLabel(f.node) : 'Connect';
    button.disabled = !canMutate() || commandBusy || !linksKnown;
    button.onclick = () => sendCommand(connected ? 'disconnect-node' : 'connect-node', String(f.node));
    right.append(links, button);
    row.append(dot, details, right);
    root.appendChild(row);
  }
}

async function refresh() {
  try {
    const response = await apiFetch('/api/activity', {cache: 'no-store'});
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const data = await response.json();
    favorites = data.favorites || [];
    rememberNodeDescriptions(data);
    cacheUpdated = data.updated || 0;
    netSchedule = data.net_schedule || {updated: 0, nets: []};
    const scheduleAge = Math.round((Date.now()/1000 - (netSchedule.updated || 0)) / 60);
    const maxMinutes = netSchedule.source === 'NetWatch' ? publicConfig.netwatchMaxAge/60 : publicConfig.netsMaxAge/60;
    document.getElementById('schedule-status').textContent = netSchedule.updated && scheduleAge >= 0 && scheduleAge <= maxMinutes
      ? (netSchedule.source || 'AllStar Nets') + ': ' + (netSchedule.nets || []).length + ' AllStar entries · cached ' + scheduleAge + 'm ago' +
        (netSchedule.source === 'NetWatch' ? ' · actual start/end times' : ' · estimated durations (fallback)')
      : 'Net schedule unavailable or stale; ordinary activity display continues.';
    await refreshLinks();
    render();
  } catch (err) {
    document.getElementById('message').textContent = 'Unable to read activity cache: ' + err.message;
  }
}

function observedLinkState(node) {
  return directLinkStates.get(String(node))?.state || 'unknown';
}

function disconnectLabel(node) {
  const state = observedLinkState(node);
  return state === 'connecting' ? 'Cancel connection' : state === 'established' ? 'Disconnect' : 'Disconnect (unverified)';
}

async function refreshLinks() {
  try {
    const response = await apiFetch('/api/links', {cache: 'no-store'});
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const data = await response.json();
    directLinks = data.links || [];
    directLinkStates = new Map((data.link_states || []).map(link => [String(link.node), link]));
    linksKnown = true;
    document.getElementById('link-status').textContent =
      directLinks.length ? '__LOCAL_NODE__ directly linked to: ' + directLinks.map(node => node + ' (' + observedLinkState(node) + ')').join(', ') : '__LOCAL_NODE__: No direct links';
  } catch (err) {
    linksKnown = false;
    document.getElementById('link-status').textContent = 'Connection status unavailable: ' + err.message;
  }
}

async function sendCommand(action, node = null) {
  if (!canMutate()) { document.getElementById('control-status').textContent='Administrator login required or controls disabled'; return; }
  if (commandBusy) return;
  commandBusy = true;
  const buttons = document.querySelectorAll('.radio-buttons button, .node-button');
  const status = document.getElementById('control-status');
  buttons.forEach(b => b.disabled = true);
  status.textContent = (action === 'stop' || action.startsWith('disconnect'))
    ? 'Disconnecting; waiting for confirmed removal…'
    : 'Updating links; waiting for an established connection…';
  try {
    const response = await apiFetch('/api/control', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Scanner-Control': '1'},
      body: JSON.stringify({action, node}),
      cache: 'no-store'
    });
    const result = await response.json();
    status.textContent = (response.ok ? '' : 'Error: ') + (result.message || 'No response');
    await refresh();
  } catch (err) {
    status.textContent = 'Error: ' + err.message;
  } finally {
    commandBusy = false;
    render();
    document.querySelectorAll('.radio-buttons button').forEach(b => b.disabled = !canMutate());
  }
}

refresh();
setInterval(refresh, publicConfig.refreshMs);




// KC1RAY-NETS-TAB-V1: presentation-only Nets view. No extra AllStarLink requests.
(() => {
  const HORIZON_MS = 24 * 3600 * 1000;
  const root = document.getElementById('nodes');
  const controls = document.querySelector('.controls');
  if (!root || !controls || !document.getElementById('activeBtn')) return;

  const tab = document.createElement('button');
  tab.type = 'button';
  tab.id = 'netsBtn';
  tab.textContent = 'Nets';
  controls.appendChild(tab);  // Immediately to the right of All.

  const panel = document.createElement('section');
  panel.id = 'nets-tab-panel';
  panel.className = 'panel';
  panel.hidden = true;
  panel.style.marginTop = '12px';
  panel.innerHTML = '<h2>Nets — Now & Next 24 Hours</h2>';
  const status = document.createElement('p');
  status.className = 'muted';
  const list = document.createElement('div');
  list.id = 'nets-tab-list';
  const actionNotice = document.createElement('p');
  actionNotice.id = 'net-action-notice';
  actionNotice.setAttribute('role', 'status');
  actionNotice.setAttribute('aria-live', 'polite');
  actionNotice.style.fontSize = '.85rem';
  actionNotice.style.color = '#cbd5e1';
  panel.append(status, actionNotice, list);
  root.insertAdjacentElement('afterend', panel);

  const scannerElements = [
    document.querySelector('.summary'),
    document.querySelector('section.panel'),
    document.getElementById('message'),
    document.getElementById('link-status'),
    document.getElementById('net-status'),
    root
  ].filter(Boolean);

  let schedule = [];
  let favoriteNodes = new Set();
  let lastGoodDownload = 0;
  let problem = '';
  let netActionBusy = false;
  const originalSetFilter = setFilter;

  setFilter = function(value) {
    if (value === 'nets') {
      // The original renderer only understands active/all. Leave its filter
      // untouched while opening the standalone schedule view.
      document.getElementById('activeBtn').classList.remove('selected');
      document.getElementById('allBtn').classList.remove('selected');
      tab.classList.add('selected');
      panel.hidden = false;
      for (const el of scannerElements) el.hidden = true;
      renderSchedule();
      fetchSchedule();
    } else {
      tab.classList.remove('selected');
      panel.hidden = true;
      for (const el of scannerElements) el.hidden = false;
      originalSetFilter(value);
    }
  };
  tab.addEventListener('click', () => setFilter('nets'));

  // This data format uses weekday 0=Monday ... 6=Sunday.
  // A 'day' string is also accepted to tolerate older daily-cache versions.
  const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
  function getWeekday(net) {
    if (net.weekday !== undefined && net.weekday !== null && net.weekday !== '') {
      const n = Number(net.weekday);
      if (Number.isInteger(n) && n >= 0 && n <= 6) return n;
    }
    const index = days.findIndex(d => d.toLowerCase() === String(net.day || '').toLowerCase());
    return index >= 0 ? index : null;
  }

  function netTimes(net, now) {
    return netOccurrences(net, now.getTime());
  }

  const localFormat = new Intl.DateTimeFormat(undefined, {
    weekday: 'short', month: 'short', day: 'numeric',
    hour: 'numeric', minute: '2-digit', timeZoneName: 'short'
  });

  function renderSchedule() {
    if (panel.hidden) return;
    const nowMs = Date.now();
    const matches = [];
    for (const n of schedule) {
      const node = String(n.node ?? '').trim();
      if (!/^\d{3,7}$/.test(node)) continue;
      for (const t of netTimes(n, new Date(nowMs))) {
        if (t.start <= nowMs && nowMs < t.end) {
          matches.push({net:n, node, start:t.start, end:t.end, underway:true});
        } else if (t.start > nowMs && t.start <= nowMs + HORIZON_MS) {
          matches.push({net:n, node, start:t.start, end:t.end, underway:false});
        }
      }
    }
    matches.sort((a,b) => (a.underway === b.underway ? a.start-b.start : a.underway ? -1 : 1) || a.node.localeCompare(b.node));
    list.replaceChildren();
    if (!schedule.length) {
      status.textContent = problem || 'No cached net schedule available.';
      return;
    }
    status.textContent = matches.length + ' scheduled net' + (matches.length === 1 ? '' : 's') +
      ' currently scheduled or starting in the next 24 hours. Times shown in your phone’s local time.' +
      (lastGoodDownload && Date.now()/1000-lastGoodDownload > (netSchedule.source === 'NetWatch' ? publicConfig.netwatchMaxAge : publicConfig.netsMaxAge) ? ' Schedule may be outdated.' : '');
    if (!matches.length) {
      status.textContent = 'No nets scheduled in the next 24 hours.';
      return;
    }
    for (const entry of matches) {
      const n = entry.net;
      const item = document.createElement('div');
      item.className = 'node';
      item.style.alignItems = 'start';
      const details = document.createElement('div');
      details.className = 'details';
      const title = document.createElement('div');
      title.className = 'name';
      title.textContent = String(n.name || 'Unnamed net');
      const state = document.createElement('span');
      state.className = 'net-badge' + (entry.underway ? '' : ' scheduled');
      state.textContent = entry.underway ? '\u00a0\u00a0Scheduled now' : '\u00a0\u00a0Upcoming Net';
      title.appendChild(state);
      const info = document.createElement('div');
      info.className = 'meta';
      info.textContent = nodeInfoLine(entry.node,
        favoriteNodes.has(entry.node) ? 'In your favorites' : 'Not in favorites');
      const when = document.createElement('div');
      when.className = 'net-details';
      when.textContent = localFormat.format(new Date(entry.start)) + ' – ' +
        new Date(entry.end).toLocaleTimeString([], {hour:'numeric',minute:'2-digit',timeZoneName:'short'}) +
        (entry.underway ? ' · Scheduled window (RF activity not confirmed)' : '');
      details.append(title, info, when);
      // Each multi-node NetWatch net is already listed once per AllStar node.
      // Let the operator try any listed node before deciding to save it.
      const actions = document.createElement('div');
      actions.className = 'net-actions';
      const connected = directLinks.includes(entry.node);
      const connect = document.createElement('button');
      connect.type = 'button';
      connect.className = 'net-action-connect' + (connected ? ' disconnect' : '');
      connect.textContent = connected ? disconnectLabel(entry.node) : 'Connect';
      connect.disabled = !canMutate() || netActionBusy || commandBusy || !linksKnown;
      connect.onclick = () => netControl(connected ? 'disconnect-net' : 'connect-net', entry.node);
      const add = document.createElement('button');
      add.type = 'button';
      add.className = 'net-action-favorite';
      const alreadyFavorite = favoriteNodes.has(entry.node);
      add.textContent = alreadyFavorite ? 'In Favorites' : 'Add to Favorites';
      add.disabled = !canMutate() || netActionBusy || alreadyFavorite || !/^\d{4,7}$/.test(entry.node);
      add.onclick = () => netAddFavorite(entry.node, String(n.name || 'Node ' + entry.node));
      actions.append(connect, add);
      details.appendChild(actions);
      try {
        const url = new URL(String(n.url || ''));
        if (url.protocol === 'https:' &&
            publicConfig.detailHosts.includes(url.hostname)) {
          const anchor = document.createElement('a');
          anchor.href = url.href;
          anchor.target = '_blank';
          anchor.rel = 'noopener noreferrer';
          anchor.textContent = 'Net details';
          anchor.style.display = 'inline-block';
          anchor.style.marginTop = '5px';
          anchor.style.color = '#93c5fd';
          details.appendChild(anchor);
        }
      } catch (_) {}
      item.appendChild(details);
      list.appendChild(item);
    }
  }

  async function netControl(action, node) {
    if (netActionBusy || commandBusy) return;
    netActionBusy = true;
    actionNotice.textContent = 'Sending ' + (action === 'connect-net' ? 'Connect' : 'Disconnect') + ' for node ' + node + '…';
    renderSchedule();
    try {
      // Reuse existing 15-second cooldown, locking, direct-link tracking and radio commands.
      await sendCommand(action, node);
      actionNotice.textContent = document.getElementById('control-status').textContent;
      await refreshLinks();
    } finally {
      netActionBusy = false;
      renderSchedule();
    }
  }

  async function netAddFavorite(node, name) {
    if (netActionBusy) return;
    netActionBusy = true;
    actionNotice.textContent = 'Adding node ' + node + ' to Favorites…';
    renderSchedule();
    try {
      const resp = await apiFetch('/api/favorites', {
        method: 'POST', cache: 'no-store',
        headers: {'Content-Type':'application/json','X-Scanner-Control':'1'},
        body: JSON.stringify({action:'add', node, name: name.slice(0,160)})
      });
      const result = await resp.json();
      if (!resp.ok) throw new Error(result.message || 'HTTP ' + resp.status);
      favoriteNodes = new Set((result.favorites || []).map(f => String(f.node)));
      actionNotice.textContent = 'Node ' + node + ' added to Favorites. The live monitor will pick it up automatically.';
      await refresh();
    } catch (error) {
      actionNotice.textContent = 'Unable to add favorite: ' + error.message;
    } finally {
      netActionBusy = false;
      renderSchedule();
    }
  }

  let inFlight = false;
  async function fetchSchedule() {
    if (inFlight) return;
    inFlight = true;
    try {
      // Local cached JSON only: does NOT contact AllStarLink or the net directory.
      const resp = await apiFetch('/api/activity', {cache:'no-store'});
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      const entry = data.net_schedule || {};
      if (!Array.isArray(entry.nets)) throw new Error('Net schedule is invalid');
      schedule = entry.nets;
      rememberNodeDescriptions(data);
      favoriteNodes = new Set((data.favorites || []).map(f => String(f.node)));
      lastGoodDownload = Number(entry.updated || 0);
      problem = '';
    } catch (error) {
      problem = 'Unable to read cached net schedule: ' + error.message;
      // Keep last valid data on a transient request failure.
    } finally {
      inFlight = false;
      renderSchedule();
    }
  }

  fetchSchedule();
  setInterval(() => { if (!panel.hidden) { renderSchedule(); fetchSchedule(); } }, 60000);
  // Reflect Connect/Disconnect status promptly while Nets is visible.
  setInterval(() => { if (!panel.hidden) renderSchedule(); }, publicConfig.refreshMs);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !panel.hidden) fetchSchedule();
  });
})();


// KC1RAY-FAVORITES-V1: local Favorites manager, no external API calls.
(() => {
  const controls = document.querySelector('.controls');
  const root = document.getElementById('nodes');
  if (!controls || !root || !document.getElementById('allBtn')) return;
  const tab = document.createElement('button');
  tab.id = 'favoritesBtn';
  tab.hidden = true;
  tab.type = 'button';
  tab.textContent = 'Favorites';
  controls.appendChild(tab);

  const panel = document.createElement('section');
  panel.className = 'panel';
  panel.id = 'favorites-panel';
  panel.hidden = true;
  panel.innerHTML = `<h2>Manage Favorites</h2>
    <p class="muted">Changes are saved locally and reloaded automatically.</p>
    <div id="fav-message" role="status" aria-live="polite"></div>
    <form id="fav-add" style="display:grid;grid-template-columns:1fr 2fr auto;gap:6px;margin:12px 0">
      <input name="node" placeholder="Node #" inputmode="numeric" required pattern="[0-9]{4,7}" style="min-width:0;padding:10px;border-radius:7px">
      <input name="name" placeholder="Description" required maxlength="160" style="min-width:0;padding:10px;border-radius:7px">
      <button type="submit">Add</button>
    </form>
    <div id="fav-items"></div>`;
  root.insertAdjacentElement('afterend', panel);
  const items = panel.querySelector('#fav-items');
  const message = panel.querySelector('#fav-message');
  const form = panel.querySelector('#fav-add');
  let entries = [];
  let busy = false;
  const hide = () => [
    document.querySelector('.summary'),
    document.querySelector('section.panel'),
    document.getElementById('message'),
    document.getElementById('link-status'),
    document.getElementById('net-status'), root
  ].filter(Boolean);
  const oldSetFilter = setFilter;
  setFilter = function(value) {
    if (value === 'favorites') {
      oldSetFilter('all'); // Also closes the Nets view, if it was open.
      for (const el of hide()) el.hidden = true;
      panel.hidden = false;
      tab.classList.add('selected');
      loadFavorites();
    } else {
      panel.hidden = true;
      tab.classList.remove('selected');
      for (const el of hide()) el.hidden = false;
      oldSetFilter(value);
    }
  };
  tab.addEventListener('click', () => setFilter('favorites'));

  function button(label, handler, disabled=false) {
    const el = document.createElement('button');
    el.type = 'button';
    el.textContent = label;
    el.style.padding = '8px';
    el.disabled = !canMutate() || disabled || busy;
    el.addEventListener('click', handler);
    return el;
  }
  function draw() {
    items.replaceChildren();
    for (let i = 0; i < entries.length; i++) {
      const f = entries[i];
      const row = document.createElement('div');
      row.className = 'node';
      row.style.flexWrap = 'wrap';
      const details = document.createElement('div');
      details.className = 'details';
      const title = document.createElement('div');
      title.className = 'name';
      title.textContent = f.name;
      const subtitle = document.createElement('div');
      subtitle.className = 'meta';
      subtitle.textContent = '#' + (i + 1) + ' · ' + nodeInfoLine(f.node);
      details.append(title, subtitle);
      const actions = document.createElement('div');
      actions.style.display = 'flex';
      actions.style.gap = '5px';
      actions.append(
        button('↑', () => change('up', f.node), i === 0),
        button('↓', () => change('down', f.node), i === entries.length - 1),
        button('Edit', () => {
          const name = prompt('Name/description for node ' + f.node, f.name);
          if (name !== null && name.trim()) change('edit', f.node, name.trim());
        }),
        button('Remove', () => {
          if (confirm('Remove node ' + f.node + ' from favorites?')) change('remove', f.node);
        })
      );
      row.append(details, actions);
      items.appendChild(row);
    }
    if (!entries.length) items.textContent = 'No favorites yet. Add a node above.';
  }
  document.addEventListener('node-descriptions-updated', () => { if (!panel.hidden) draw(); });
  async function loadFavorites() {
    try {
      const response = await apiFetch('/api/favorites', {cache: 'no-store'});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      entries = data.favorites || [];
      message.textContent = entries.length + ' favorites. Use arrows to change priority.';
      draw();
    } catch (error) {
      message.textContent = 'Cannot load favorites: ' + error.message;
    }
  }
  async function change(action, node, name) {
    if (busy) return;
    busy = true;
    draw();
    message.textContent = 'Saving…';
    try {
      const response = await apiFetch('/api/favorites', {
        method: 'POST', cache: 'no-store',
        headers: {'Content-Type':'application/json','X-Scanner-Control':'1'},
        body: JSON.stringify({action, node, name})
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'HTTP ' + response.status);
      entries = data.favorites;
      message.textContent = 'Saved. Monitor will reload the updated favorites automatically.';
      if (typeof refresh === 'function') refresh();
    } catch (error) {
      message.textContent = 'Save failed: ' + error.message;
    } finally {
      busy = false;
      draw();
    }
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    const data = new FormData(form);
    const node = String(data.get('node') || '').trim();
    const name = String(data.get('name') || '').trim();
    if (node && name) change('add', node, name).then(() => { if (!busy && message.textContent.startsWith('Saved')) form.reset(); });
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !panel.hidden) loadFavorites();
  });
})();

</script>
</body>
</html>'''


def direct_links(timeout=8):
    return Asterisk(ASTERISK, LOCAL_NODE).links(timeout=timeout)


def render_html(nonce=None):
    public = {
        'controlsEnabled': CONFIG['web']['controls_enabled'],
        'anonymousView': CONFIG['web']['anonymous_view'],
        'statsMaxAge': CONFIG['monitor']['max_stats_age_seconds'],
        'netwatchMaxAge': NETWATCH_MAX_AGE_SECONDS,
        'netsMaxAge': NET_CACHE_MAX_AGE_SECONDS,
        'netDuration': NET_DURATION_MINUTES,
        'refreshMs': CONFIG['web']['refresh_seconds'] * 1000,
        'detailHosts': sorted({urlsplit(source['details_url']).hostname
                               for source in CONFIG['schedules'].values()}),
    }
    nonce = nonce or secrets.token_urlsafe(24)
    return HTML.replace('__LOCAL_NODE__', LOCAL_NODE).replace(
        '__PUBLIC_CONFIG__', json.dumps(public).replace('<', r'\u003c')).replace(
        '__APP_AUTH__', APP_AUTH).replace('__URL_PREFIX__',json.dumps(CONFIG['web']['url_prefix'])).replace('href="/login"','href="'+CONFIG['web']['url_prefix']+'/login"').replace('<script>', '<script nonce="'+nonce+'">')


def favorite_numbers():
    return {entry['node'] for entry in favorites_store.read()}


def load_schedule():
    for key, path, maximum, label in (
        ('netwatch', NETWATCH_CACHE, NETWATCH_MAX_AGE_SECONDS, 'NetWatch'),
        ('allstarnets', NETS_CACHE, NET_CACHE_MAX_AGE_SECONDS, 'AllStar Nets'),
    ):
        if not CONFIG['schedules'][key]['enabled']:
            continue
        try:
            schedule = json.loads(path.read_text())
            age = time.time() - float(schedule.get('updated', 0))
            if not 0 <= age <= maximum or not isinstance(schedule.get('nets'), list):
                continue
            if key == 'netwatch' and schedule.get('source') != 'NetWatch':
                continue
            if key == 'allstarnets':
                schedule['default_duration_minutes'] = NET_DURATION_MINUTES
            return schedule | {'source': label}
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return {'updated': 0, 'nets': [], 'default_duration_minutes': NET_DURATION_MINUTES}


def scheduled_net_numbers():
    return {str(e.get('node')) for e in load_schedule()['nets'] if isinstance(e, dict)
            and re.fullmatch(r'\d{3,7}', str(e.get('node', '')))}


def activity_payload():
    try:
        payload = json.loads(CACHE.read_text())
        samples = {str(f['node']): f for f in payload.get('favorites', [])}
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        payload, samples = {'updated': 0}, {}
    # Store owns order/names/membership; cache owns only activity observations.
    payload['favorites'] = [samples.get(f['node'], {}) | f for f in favorites_store.read()]
    payload['local_node'] = LOCAL_NODE
    payload['net_schedule'] = load_schedule()
    return payload


def run_link_action(action, node):
    if action not in ('connect-node','disconnect-node','connect-net','disconnect-net'):
        raise ValueError('Invalid action')
    is_net_action = action in ('connect-net', 'disconnect-net')
    if not isinstance(node, str) or not re.fullmatch(r'\d{3,7}' if is_net_action else r'\d{4,7}', node):
        raise ValueError('Invalid node')
    if not is_net_action and node not in favorite_numbers():
        raise ValueError('Node is not in the Favorites list')
    if action == 'connect-net' and node not in scheduled_net_numbers():
        raise ValueError('Node is no longer in the cached Nets directory')
    is_connect = action in ('connect-node', 'connect-net')
    with operation_lock(SCANNER_LOCK):
        client = Asterisk(ASTERISK, LOCAL_NODE)
        controller = LinkController(direct_links, client.command)
        return perform('connect' if is_connect else 'disconnect', node, controller,
                       SCANNER_STATE, LOCAL_NODE)


def scan_action(action):
    # Selection and transitions stay in-process in the restricted broker. CLI
    # first/next/stop --apply remains available to existing trusted local callers.
    import scanner
    return scanner.scan(action, True)


class Handler(BaseHTTPRequestHandler):
    server_version = 'HubScanner'
    sys_version = ''

    def log_message(self,format,*args):
        pass # never log request lines, query strings, bodies, cookies or tokens

    def send_body(self,status,content_type,body):
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        nonce=getattr(self,'csp_nonce','')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")
        for name,value in getattr(self,'response_headers',[]):
            self.send_header(name,value)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_body(self,status,body):
        self.send_body(status,'application/json',json.dumps(body).encode())

    def reply(self,status,message):
        self.json_body(status,{'message':message})

    def prepare(self):
        self.response_headers=[]
        self.csp_nonce=secrets.token_urlsafe(24)
        prefix=CONFIG['web']['url_prefix']
        if prefix:
            if self.path!=prefix and not self.path.startswith(prefix+'/'):
                raise Denied(404,'Not found')
            self.path=self.path[len(prefix):] or '/'
        self.context=request_context(self.headers,self.client_address[0],CONFIG['web'])
        for name in ('Origin','X-CSRF-Token','Cookie'):
            if len(self.headers.get_all(name,[]))>1:
                raise Denied(400,'Duplicate security header')
        self.auth=self.server.security
        self.auth.rates.take(('read',self.context.client),CONFIG['auth']['read_attempts'],CONFIG['auth']['read_window_seconds'])
        self.token=cookie_token(self.headers,name=self.prefix_cookie_name()) if prefix else cookie_token(self.headers)
        self.session=self.auth.sessions.lookup(self.token,self.context.secure)
        if self.session and self.session.username and not self.context.transport_allowed:
            raise Denied(403,'HTTPS required for administrator access')

    def read_json(self):
        if self.headers.get('Transfer-Encoding') is not None or len(self.headers.get_all('Content-Length',[]))!=1:
            raise Denied(400,'Invalid request framing')
        if len(self.headers.get_all('Content-Type',[]))!=1 or self.headers.get('Content-Type','').split(';')[0].strip().lower()!='application/json':
            raise Denied(415,'JSON required')
        try:
            length=int(self.headers['Content-Length'])
            if not 0<length<=4096:
                raise ValueError()
            raw=self.rfile.read(length)
            if len(raw)!=length:
                raise ValueError()
            def unique(pairs):
                result={}
                for key,value in pairs:
                    if key in result:
                        raise ValueError()
                    result[key]=value
                return result
            def invalid_constant(value):
                raise ValueError()
            payload=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid_constant)
            if not isinstance(payload,dict):
                raise ValueError()
            return payload
        except (ValueError,UnicodeError,RecursionError):
            raise Denied(400,'Invalid JSON request') from None

    def check_origin(self):
        origin=self.headers.get('Origin')
        if origin is not None and origin!=self.context.origin:
            raise Denied(403,'Origin not permitted')
        if self.headers.get('Sec-Fetch-Site')=='cross-site':
            raise Denied(403,'Cross-site request not permitted')

    def authorize_mutation(self,rate_limit=True):
        self.check_origin()
        self.auth.authorize(self.session,self.headers.get('X-CSRF-Token'),mutation=True)
        if rate_limit:
            self.auth.rates.take(('sensitive',self.session.username),CONFIG['auth']['sensitive_attempts'],CONFIG['auth']['sensitive_window_seconds'])
        self.auth.sessions.touch(self.session)

    def prefix_cookie_name(self):
        return 'kc1ray_hubscanner_secure_session' if self.context.secure else 'kc1ray_hubscanner_session'

    def session_header(self,token,*,delete=False):
        prefix=CONFIG['web']['url_prefix']
        if not prefix:
            return session_cookie(token,self.context.secure,delete=delete)
        return session_cookie(token,self.context.secure,delete=delete,path=prefix+'/',name=self.prefix_cookie_name())

    def session_response(self):
        if self.session is None:
            self.auth.rates.take(('bootstrap',self.context.client),CONFIG['auth']['login_attempts']*2,CONFIG['auth']['login_window_seconds'])
            self.token,self.session=self.auth.sessions.create(self.context.secure)
            self.response_headers.append(('Set-Cookie',self.session_header(self.token)))
        self.json_body(200,{'authenticated':self.session.username is not None,
                            'csrf':self.session.csrf,'transport_safe':self.context.transport_allowed,'unencrypted_lan':self.context.lan_http})

    def do_GET(self):
        try:
            self.prepare()
            if self.path in ('/','/login'):
                signed_in=self.session is not None and self.session.username is not None
                if self.path=='/login' or (not signed_in and not CONFIG['web']['anonymous_view']):
                    html=LOGIN_HTML.replace('__NONCE__',self.csp_nonce).replace('__URL_PREFIX__',json.dumps(CONFIG['web']['url_prefix']))
                else:
                    self.auth.authorize(self.session,None,anonymous=CONFIG['web']['anonymous_view'])
                    html=render_html(self.csp_nonce)
                self.send_body(200,'text/html; charset=utf-8',html.encode())
            elif self.path=='/api/session':
                self.session_response()
            elif self.path in ('/api/activity','/api/links','/api/favorites'):
                anonymous=CONFIG['web']['anonymous_view'] and self.path!='/api/favorites'
                self.auth.authorize(self.session,None,anonymous=anonymous)
                if self.path=='/api/activity':
                    self.json_body(200,activity_payload())
                elif self.path=='/api/links':
                    self.json_body(200,rpc('links'))
                else:
                    self.json_body(200,{'favorites':favorites_store.read()})
            else:
                self.reply(404,'Not found')
        except Denied as exc:
            self.deny(exc)
        except (OSError,RuntimeError,ValueError,TypeError,KeyError):
            self.reply(503,'Requested data unavailable')

    def do_POST(self):
        # Retain the explicit maintenance switch in addition to authorization.
        if getattr(self,'path','/api/control') in ('/api/control','/api/favorites') and not CONFIG['web']['controls_enabled']:
            self.reply(403,'Mutations disabled by configuration')
            return
        try:
            self.prepare()
            if self.path in ('/api/control','/api/favorites') and not CONFIG['web']['controls_enabled']:
                raise Denied(403,'Mutations disabled by configuration')
            self.check_origin()
            if self.path=='/api/auth/login':
                payload=self.read_json()
                token,session=self.auth.login(self.context,self.token,self.session,self.headers.get('X-CSRF-Token'),payload)
                self.response_headers.append(('Set-Cookie',self.session_header(token)))
                self.json_body(200,{'authenticated':True,'csrf':session.csrf})
                return
            if self.path not in ('/api/control','/api/favorites','/api/auth/logout','/api/session/touch'):
                self.reply(404,'Not found')
                return
            self.authorize_mutation(rate_limit=self.path!='/api/auth/logout')
            payload=self.read_json()
            if self.path=='/api/auth/logout':
                if payload:
                    raise Denied(400,'Invalid logout request')
                self.auth.sessions.revoke(self.token)
                self.response_headers.append(('Set-Cookie',self.session_header('',delete=True)))
                self.json_body(200,{'authenticated':False})
            elif self.path=='/api/session/touch':
                if payload:
                    raise Denied(400,'Invalid session request')
                self.json_body(200,{'authenticated':True})
            else:
                op='control' if self.path=='/api/control' else 'favorites'
                self.json_body(200,rpc(op,payload))
        except Denied as exc:
            self.deny(exc)
        except (ValueError,TypeError,KeyError):
            self.reply(400,'Invalid request')
        except (OSError,RuntimeError):
            self.reply(503,'Operation unavailable')

    def deny(self,error):
        self.response_headers=getattr(self,'response_headers',[])
        if error.retry_after is not None:
            self.response_headers.append(('Retry-After',str(max(1,int(error.retry_after)))))
        self.reply(error.status,error.message)


class WebServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,security):
        self.security=security
        self.slots=threading.BoundedSemaphore(CONFIG['web']['max_workers'])
        super().__init__(address,Handler)

    def get_request(self):
        request,address=super().get_request()
        request.settimeout(CONFIG['web']['request_timeout_seconds'])
        return request,address

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request,address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self,request,address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()

    def handle_error(self,request,address):
        pass # never include raw requests/credentials in a traceback


def main():
    require_node()
    validate_web_identity()
    security=Security(CONFIG['auth'],Credentials(CONFIG['auth']['credentials_file']))
    with WebServer((HOST,PORT),security) as server:
        print('KC1RAY Hub Scanner web interface started',flush=True)
        server.serve_forever()


if __name__=='__main__':
    main()
