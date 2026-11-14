"""Small same-origin authentication UI; no passwords or session tokens in storage."""
LOGIN_HTML=r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Hub Scanner — Sign in</title>
<style>body{font:18px system-ui;background:#101720;color:#f1f5f9;max-width:28rem;margin:4rem auto;padding:1rem}input,button{display:block;padding:.8rem;margin:.8rem 0;box-sizing:border-box;width:100%}a{color:#93c5fd}</style></head>
<body><h1>Hub Scanner</h1><h2>Administrator sign in</h2>
<form id="login"><label>Username<input name="username" autocomplete="username" required maxlength="64"></label>
<label>Passphrase<input name="password" type="password" autocomplete="current-password" required minlength="8"></label>
<button id="submit" disabled>Sign in</button></form><p id="status" role="status">Checking connection…</p>
<script nonce="__NONCE__">
const hubPrefix=__URL_PREFIX__;
function hubUrl(path){return hubPrefix+path;}
let csrf='';
const status=document.getElementById('status'),submit=document.getElementById('submit');
async function prepare(){
  const response=await fetch(hubUrl('/api/session'),{cache:'no-store'});
  const session=await response.json();
  if(!response.ok)throw new Error(session.message||'Session unavailable');
  if(session.authenticated){location.assign(hubUrl('/'));return;}
  csrf=session.csrf;
  submit.disabled=!session.transport_safe;
  status.textContent=session.unencrypted_lan?'Warning: HTTP on this trusted LAN does not encrypt your credentials or session.':(session.transport_safe?'':'Use HTTPS or explicitly configured trusted LAN access to sign in.');
}
document.getElementById('login').addEventListener('submit',async event=>{
  event.preventDefault();submit.disabled=true;
  const form=event.currentTarget;
  try{
    const response=await fetch(hubUrl('/api/auth/login'),{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},
      body:JSON.stringify({username:form.elements.username.value,password:form.elements.password.value})});
    const result=await response.json();
    form.elements.password.value='';
    if(!response.ok)throw new Error(result.message||'Sign in failed');
    location.assign(hubUrl('/'));
  }catch(error){status.textContent=error.message;submit.disabled=false;}
});
prepare().catch(error=>{status.textContent=error.message;});
</script></body></html>'''

APP_AUTH=r'''
const hubPrefix=__URL_PREFIX__;
function hubUrl(path){return hubPrefix+path;}
let authState={authenticated:false,csrf:''};
const authReady=fetch(hubUrl('/api/session'),{cache:'no-store'}).then(async response=>{
  if(!response.ok)throw new Error('Session unavailable');
  authState=await response.json();updateAccess();
}).catch(()=>{updateAccess();});
function canMutate(){return authState.authenticated&&publicConfig.controlsEnabled;}
function updateAccess(){
  const admin=document.getElementById('adminBtn');if(admin)admin.hidden=!authState.authenticated;
  const adminPanel=document.getElementById('admin-panel');if(adminPanel&&!authState.authenticated)adminPanel.hidden=true;
  document.dispatchEvent(new Event('auth-state-changed'));
  const info=document.getElementById('account-status');
  if(info)info.textContent=authState.authenticated?'Administrator':'Read-only viewer';
  const logout=document.getElementById('logout');if(logout)logout.hidden=!authState.authenticated;
  const login=document.getElementById('signin');if(login)login.hidden=authState.authenticated;
  document.querySelectorAll('.radio-buttons button').forEach(button=>button.disabled=!canMutate());
  const tab=document.getElementById('favoritesBtn');if(tab)tab.hidden=!authState.authenticated;
  document.querySelectorAll('#favorites-panel input, #favorites-panel button').forEach(button=>button.disabled=!canMutate());
}
async function apiFetch(url,options={}){
  await authReady;
  const headers=new Headers(options.headers||{});
  if(options.method==='POST'){
    if(!authState.authenticated)throw new Error('Administrator login required');
    headers.set('X-CSRF-Token',authState.csrf);
  }
  const response=await fetch(hubUrl(url),{...options,headers});
  if(response.status===401){
    authState={authenticated:false,csrf:''};updateAccess();
    if(!publicConfig.anonymousView)location.assign(hubUrl('/login'));
  }
  return response;
}
document.addEventListener('click',event=>{
  const button=event.target.closest('button[data-action]');if(!button)return;
  const action=button.dataset.action;
  if(['first','next','stop'].includes(action))sendCommand(action);
  else if(action==='wake')toggleWakeLock();
  else if(action.startsWith('filter-'))setFilter(action.slice(7));
});
document.getElementById('logout').addEventListener('click',async()=>{
  try{await apiFetch('/api/auth/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});}
  finally{location.assign(hubUrl('/login'));}
});
let lastTouch=0;
function touchSession(){
  if(!authState.authenticated||Date.now()-lastTouch<60000)return;
  lastTouch=Date.now();
  apiFetch('/api/session/touch',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(()=>{});
}
document.addEventListener('pointerdown',touchSession,{passive:true});
document.addEventListener('keydown',touchSession);
'''
