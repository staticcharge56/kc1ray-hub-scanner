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
      <button type="submit">Save settings</button> <button type="button" id="admin-cancel">Cancel</button> <button type="button" id="admin-reload">Reload settings/status</button>
    </form>
    <h3>Change administrator password</h3>
    <form id="admin-password" style="max-width:34rem;display:grid;gap:10px">
      <label>Current password <input name="current_password" type="password" autocomplete="current-password" required maxlength="1024" style="width:100%;box-sizing:border-box;padding:8px"></label>
      <label>New password <input name="new_password" type="password" autocomplete="new-password" required minlength="8" maxlength="1024" style="width:100%;box-sizing:border-box;padding:8px"></label>
      <label>Confirm new password <input name="confirmation" type="password" autocomplete="new-password" required minlength="8" maxlength="1024" style="width:100%;box-sizing:border-box;padding:8px"></label>
      <button type="submit">Change password and sign in again</button>
    </form>
    <h3>System status</h3><div id="admin-status" style="overflow-wrap:anywhere"></div>`;
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
  function disable(value){busy=value;panel.querySelectorAll('input,select,button').forEach(el=>el.disabled=value);}
  function fields(settings){
    const select=form.elements.refresh_seconds;select.replaceChildren();
    const choices=[5,10,15,30,60];if(!choices.includes(settings.refresh_seconds))choices.push(settings.refresh_seconds);
    for(const seconds of choices){const option=document.createElement('option');option.value=String(seconds);option.textContent=seconds+' seconds'+([5,10,15,30,60].includes(seconds)?'':' (current)');select.appendChild(option);}
    select.value=String(settings.refresh_seconds);
    for(const key of ['controls_enabled','anonymous_view','netwatch_enabled','allstarnets_enabled'])form.elements[key].checked=settings[key];
  }
  const stamp=value=>typeof value==='number'&&value>0?new Date(value*1000).toLocaleString():'Unavailable';
  function status(data){
    const root=panel.querySelector('#admin-status');root.replaceChildren();
    const entries=[['Version',data.status.version],['Local ASL3 node',data.status.local_node],['Web access',data.status.web_access],['Last successful monitor sample',stamp(data.status.last_monitor_update)]];
    for(const [unit,state] of Object.entries(data.status.services))entries.push([unit,state.active_state+' / '+state.enabled_state]);
    for(const [label,value] of entries){const line=document.createElement('p');line.textContent=label+': '+value;root.appendChild(line);}
    for(const source of ['netwatch','allstarnets'])panel.querySelector('#admin-'+source+'-update').textContent='Last successful update: '+stamp(data.source_updates[source]);
    if(data.recovery_required)message.textContent='An administration operation needs recovery. Review the helper service before making more changes.';
  }
  async function load(){
    if(busy)return;disable(true);message.textContent='Loading settings…';
    try{const response=await apiFetch('/api/admin',{cache:'no-store'});const data=await response.json();if(!response.ok)throw Error(data.message||'Administration unavailable');saved=data;fields(data.settings);message.textContent='Settings loaded.';status(data);}
    catch(error){message.textContent=error.message;}finally{disable(false);}
  }
  panel.querySelector('#admin-reload').onclick=load;
  panel.querySelector('#admin-cancel').onclick=()=>{if(saved){fields(saved.settings);message.textContent='Unsaved changes discarded.';}password.reset();};
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy||!saved)return;
    const settings={refresh_seconds:Number(form.elements.refresh_seconds.value)};
    for(const key of ['controls_enabled','anonymous_view','netwatch_enabled','allstarnets_enabled'])settings[key]=form.elements[key].checked;
    let confirm_disable=false;
    if(saved.settings.controls_enabled&&!settings.controls_enabled){confirm_disable=confirm('Disable radio controls and favorites writes? Existing radio links will not be changed.');if(!confirm_disable)return;}
    disable(true);message.textContent='Saving settings…';
    try{
      const response=await apiFetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:saved.revision,settings,confirm_disable})});const data=await response.json();
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
