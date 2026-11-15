"""Administrator-only navigation and forms; authorization always remains server-side."""
ADMIN_UI=r'''
(() => {
  const controls=document.querySelector('.controls');
  const tab=document.createElement('button');tab.type='button';tab.id='adminBtn';tab.textContent='Admin';tab.hidden=true;controls.appendChild(tab);
  const panel=document.createElement('section');panel.id='admin-panel';panel.className='panel';panel.hidden=true;
  panel.innerHTML=`<h2>Administration</h2>
    <p id="admin-message" role="status" aria-live="polite"></p>
    <form id="admin-settings">
      <h3>General settings</h3>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px">
        <label>Dashboard refresh interval <select name="refresh_seconds" style="padding:8px"></select></label>
        <label><input type="checkbox" name="controls_enabled"> Enable radio controls</label>
        <label><input type="checkbox" name="anonymous_view"> Anonymous viewing</label>
      </div>
      <p class="muted">Anonymous viewing exposes activity, favorites, schedules and links to anyone who can reach this dashboard. It never permits changes. The existing radio maintenance switch also disables favorites writes; Admin remains available.</p>
      <h3>Activity sources</h3>
      <p><label><input type="checkbox" name="netwatch_enabled"> NetWatch</label> <span id="admin-netwatch-update"></span></p>
      <p><label><input type="checkbox" name="allstarnets_enabled"> AllStar Nets</label> <span id="admin-allstarnets-update"></span></p>
      <p class="muted">These switches manage the existing timers. Cached schedules and history are retained. Dashboard refresh does not change monitor/API polling.</p>
      <h3>Advanced settings</h3>
      <label>Local ASL3 node <select name="local_node"></select></label><p class="muted" id="admin-node-discovery"></p>
      <p class="muted">Only locally discovered nodes can be selected. Clear the scanner selection with STOP before switching. Existing Asterisk links are left unchanged. A node change restarts the broker and monitor; active radio operations block Save.</p>
      <label>Connection cooldown (15–300 seconds) <input type="number" name="cooldown_seconds" min="15" max="300" required></label>
      <h3>Monitoring settings</h3>
      <label>Activity polling interval per favorite slot (4–300 seconds) <input type="number" name="poll_interval_seconds" min="4" max="300" required></label>
      <label>Statistics freshness (60–3600 seconds) <input type="number" name="max_stats_age_seconds" min="60" max="3600" required></label>
      <label>Recent activity window (60–3600 seconds) <input type="number" name="activity_window_seconds" min="60" max="3600" required></label>
      <p class="muted">These backend settings differ from dashboard refresh. A polling cycle takes at least favorite count × interval, plus request time and backoff. Short freshness windows can make healthy nodes unknown; longer windows retain older observations. Changes restart only the monitor and preserve history/backoff.</p>
      <label>NetWatch interval (30–1440 minutes) <input type="number" name="netwatch_interval_minutes" min="30" max="1440"></label>
      <label>AllStar Nets calendar <select name="allstarnets_frequency"><option value="daily">Daily at 03:00 UTC</option><option value="weekly">Sunday at 03:00 UTC</option></select></label>
      <p class="muted">Timer jitter, NetWatch boot activation and AllStar Nets catch-up remain enabled. Restarting an enabled timer may trigger an existing due/catch-up import. Custom timer overrides require manual review and are never replaced here.</p>
      <button type="submit">Save settings</button> <button type="button" id="admin-cancel">Cancel</button> <button type="button" id="admin-reload">Reload settings/status</button>
    </form>
    <h3>Change administrator password</h3>
    <form id="admin-password" style="max-width:34rem;display:grid;gap:10px">
      <label>Current password <input name="current_password" type="password" autocomplete="current-password" required maxlength="1024" style="width:100%;box-sizing:border-box;padding:8px"></label>
      <label>New password <input name="new_password" type="password" autocomplete="new-password" required minlength="8" maxlength="1024" style="width:100%;box-sizing:border-box;padding:8px"></label>
      <label>Confirm new password <input name="confirmation" type="password" autocomplete="new-password" required minlength="8" maxlength="1024" style="width:100%;box-sizing:border-box;padding:8px"></label>
      <button type="submit">Change password and sign in again</button>
    </form>
    <h3>System status and diagnostics</h3><button type="button" id="admin-diagnostics-refresh">Refresh Diagnostics</button><div id="admin-status" style="overflow-wrap:anywhere"></div><pre id="admin-diagnostics" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>`;
  document.getElementById('nodes').insertAdjacentElement('afterend',panel);
  const form=panel.querySelector('#admin-settings'),password=panel.querySelector('#admin-password'),message=panel.querySelector('#admin-message');
  let saved=null,busy=false;
  const base=()=>[document.querySelector('.summary'),document.querySelector('section.panel'),document.getElementById('message'),document.getElementById('link-status'),document.getElementById('net-status'),document.getElementById('nodes')].filter(Boolean);
  const oldSetFilter=window.setFilter;
  window.setFilter=function(value){
    if(value==='admin'){
      if(!authState.authenticated)return;
      oldSetFilter('all');base().forEach(el=>el.hidden=true);panel.hidden=false;tab.classList.add('selected');load();
    }else{panel.hidden=true;tab.classList.remove('selected');base().forEach(el=>el.hidden=false);oldSetFilter(value);}
  };
  tab.addEventListener('click',()=>setFilter('admin'));
  function access(){
    tab.hidden=!authState.authenticated;
    if(!authState.authenticated&&tab.classList.contains('selected')){panel.hidden=true;setFilter('all');}
  }
  document.addEventListener('auth-state-changed',access);authReady.then(access);
  function disable(value){busy=value;panel.querySelectorAll('input,select,button').forEach(el=>el.disabled=value||el.dataset.unavailable==='true');}
  function fields(settings){
    const select=form.elements.refresh_seconds;select.replaceChildren();
    const choices=[5,10,15,30,60];if(!choices.includes(settings.refresh_seconds))choices.push(settings.refresh_seconds);
    for(const seconds of choices){const option=document.createElement('option');option.value=String(seconds);option.textContent=seconds+' seconds'+([5,10,15,30,60].includes(seconds)?'':' (current)');select.appendChild(option);}
    select.value=String(settings.refresh_seconds);
    const node=form.elements.local_node;node.replaceChildren();
    const discovered=saved&&saved.local_nodes?saved.local_nodes:{nodes:[],available:false};
    for(const value of [...new Set([settings.local_node,...discovered.nodes])]){const option=document.createElement('option');option.value=value;option.textContent=value+(value===settings.local_node?' (current)':'');node.appendChild(option);}
    node.value=settings.local_node;node.dataset.unavailable=String(!discovered.available);
    panel.querySelector('#admin-node-discovery').textContent=!discovered.available?'Local-node discovery unavailable; current node is retained.':discovered.dynamic?'Static nodes shown; dynamic #exec definitions cannot be selected.':'Validated local nodes shown.';
    for(const key of ['cooldown_seconds','poll_interval_seconds','max_stats_age_seconds','activity_window_seconds']){const input=form.elements[key];input.value=String(settings[key]);const lo=key==='cooldown_seconds'?15:key==='poll_interval_seconds'?4:60,hi=key==='cooldown_seconds'||key==='poll_interval_seconds'?300:3600;input.min=String(Math.min(lo,settings[key]));input.max=String(Math.max(hi,settings[key]));}
    for(const [source,key] of [['netwatch','netwatch_interval_minutes'],['allstarnets','allstarnets_frequency']]){
      const input=form.elements[key];input.dataset.unavailable=String(!(saved&&saved.schedule_available&&saved.schedule_available[source]));
      if(settings[key]!==null)input.value=String(settings[key]);else if(key==='netwatch_interval_minutes')input.value='';
    }

    for(const key of ['controls_enabled','anonymous_view','netwatch_enabled','allstarnets_enabled'])form.elements[key].checked=settings[key];
  }
  const stamp=value=>typeof value==='number'&&value>0?new Date(value*1000).toLocaleString():'Unavailable';
  function status(data){
    const root=panel.querySelector('#admin-status');root.replaceChildren();
    const entries=[['Version',data.status.version],['Installed release',data.status.release||'Unavailable'],['Local ASL3 node',data.status.local_node],['Web access',data.status.web_access],['Last successful monitor sample',stamp(data.status.last_monitor_update)]];
    for(const [unit,state] of Object.entries(data.status.services))entries.push([unit,state.active_state+' / '+state.enabled_state]);
    for(const [label,value] of entries){const line=document.createElement('p');line.textContent=label+': '+value;root.appendChild(line);}
    for(const source of ['netwatch','allstarnets'])panel.querySelector('#admin-'+source+'-update').textContent='Last successful update: '+stamp(data.source_updates[source]);
    const diagnostic=data.diagnostics||{},connections=data.connections;
    const lines=['Activity health: '+(diagnostic.state||'unavailable'),'Minimum polling cycle: '+(diagnostic.minimum_cycle_seconds??'Unavailable')+' seconds'];
    if(connections)lines.push('Connections: '+(connections.state==='unavailable'?'Unavailable':(connections.link_states||[]).map(link=>link.node+' ('+link.state+')').join(', ')||'Disconnected'));
    for(const [source,state] of Object.entries(diagnostic.sources||{}))lines.push(source+': '+state.state+' / last update '+stamp(state.last_success));
    if(diagnostic.api)lines.push('Provider backoff: '+JSON.stringify(diagnostic.api.global_limit),'Per-node backoff: '+JSON.stringify(diagnostic.api.nodes));
    for(const warning of diagnostic.warnings||[])lines.push('Warning: '+warning);
    for(const node of diagnostic.nodes||[])lines.push('Node '+node.node+': '+node.state+' / '+node.freshness+' / last success '+stamp(node.last_success));
    lines.push('Recent application events (known summaries only):');
    if(diagnostic.recent_events===null)lines.push('Journal unavailable');
    else if(!(diagnostic.recent_events||[]).length)lines.push('No recognized recent warnings/errors');
    for(const event of diagnostic.recent_events||[])lines.push(stamp(event.time)+' '+event.unit+': '+event.message);
    panel.querySelector('#admin-diagnostics').textContent=lines.join('\n');
    if(data.recovery_required)message.textContent='An administration operation needs recovery. Review the helper service before making more changes.';
  }
  async function load(reset=true){
    if(busy)return;disable(true);message.textContent='Loading settings…';
    try{const response=await apiFetch('/api/admin',{cache:'no-store'});const data=await response.json();if(!response.ok)throw Error(data.message||'Administration unavailable');if(reset){saved=data;fields(data.settings);}message.textContent=reset?'Settings loaded.':'Diagnostics refreshed; unsaved settings retained.';status(data);}
    catch(error){message.textContent=error.message;}finally{disable(false);}
  }
  panel.querySelector('#admin-reload').onclick=()=>load();
  panel.querySelector('#admin-diagnostics-refresh').onclick=()=>load(false);
  panel.querySelector('#admin-cancel').onclick=()=>{if(saved){fields(saved.settings);message.textContent='Unsaved changes discarded.';}password.reset();};
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy||!saved)return;
    const settings={refresh_seconds:Number(form.elements.refresh_seconds.value)};
    for(const key of ['controls_enabled','anonymous_view','netwatch_enabled','allstarnets_enabled'])settings[key]=form.elements[key].checked;
    for(const key of ['cooldown_seconds','poll_interval_seconds','max_stats_age_seconds','activity_window_seconds','netwatch_interval_minutes']){
      if(form.elements[key].dataset.unavailable!=='true'&&Number(form.elements[key].value)!==saved.settings[key])settings[key]=Number(form.elements[key].value);
    }
    for(const key of ['local_node','allstarnets_frequency'])if(form.elements[key].dataset.unavailable!=='true'&&form.elements[key].value!==saved.settings[key])settings[key]=form.elements[key].value;
    let confirm_node_change=false;
    if(settings.local_node&&settings.local_node!==saved.settings.local_node){confirm_node_change=confirm('Change local ASL3 node? Clear the scanner selection with STOP first. Existing Asterisk links will not be changed. The broker and monitor may restart.');if(!confirm_node_change)return;}
    let confirm_disable=false;
    if(saved.settings.controls_enabled&&!settings.controls_enabled){confirm_disable=confirm('Disable radio controls and favorites writes? Existing radio links will not be changed.');if(!confirm_disable)return;}
    disable(true);message.textContent='Saving settings…';
    try{
      const response=await apiFetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:saved.revision,settings,confirm_disable,confirm_node_change})});const data=await response.json();
      if(!response.ok)throw Error(data.message||'Settings were not saved');saved=data;fields(data.settings);applyViewSettings(data.settings);status(data);message.textContent=data.message;
    }catch(error){message.textContent=error.message;}finally{disable(false);}
  });
  password.addEventListener('submit',async event=>{
    event.preventDefault();if(busy)return;
    if(password.elements.new_password.value!==password.elements.confirmation.value){message.textContent='New passwords do not match.';return;}
    const payload={};for(const key of ['current_password','new_password','confirmation'])payload[key]=password.elements[key].value;
    disable(true);message.textContent='Changing password…';
    try{
      const response=await apiFetch('/api/admin/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await response.json();
      if(!response.ok)throw Error(data.message||'Password was not changed');message.textContent=data.message;password.reset();setTimeout(()=>location.assign(hubUrl('/login')),1200);
    }catch(error){message.textContent=error.message;}finally{password.reset();for(const key of Object.keys(payload))payload[key]='';disable(false);}
  });
})();
'''
