require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(__dirname));

const sessions = new Map();
const states = new Map();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const env = (k) => String(process.env[k] || '').trim();
const b64u = (v) => Buffer.from(v).toString('base64url');
const rand = (n=32) => crypto.randomBytes(n).toString('base64url');
const escRedirect = (v) => /^https?:\/\//i.test(v) ? v : BASE_URL + '/';

function setCookie(res, name, value, maxAge=3600){
  const parts=[`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if(/^https:/i.test(BASE_URL)) parts.push('Secure');
  parts.push(`Max-Age=${maxAge}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}
function cookies(req){
  const out={};
  for(const p of String(req.headers.cookie||'').split(';')){
    const i=p.indexOf('='); if(i<0) continue;
    out[p.slice(0,i).trim()] = decodeURIComponent(p.slice(i+1).trim());
  }
  return out;
}
function configured(provider){
  if(provider==='google') return env('GOOGLE_CLIENT_ID') && env('GOOGLE_CLIENT_SECRET');
  if(provider==='github') return env('GITHUB_CLIENT_ID') && env('GITHUB_CLIENT_SECRET');
  if(provider==='apple') return env('APPLE_CLIENT_ID') && env('APPLE_TEAM_ID') && env('APPLE_KEY_ID') && env('APPLE_PRIVATE_KEY');
  return false;
}
function oauthError(res, provider, msg){
  res.status(503).send(`<html><body style="font-family:system-ui;background:#0d0d10;color:#fff;padding:40px"><h2>${provider} Sign In is not configured</h2><p>${msg}</p><p>Configure the provider credentials in the server environment and try again.</p><a href="/" style="color:#4da3ff">Return to WHITE DEVIL</a></body></html>`);
}

app.get('/auth/:provider', (req,res)=>{
  const provider=req.params.provider;
  if(!['google','github','apple'].includes(provider)) return res.status(404).send('Unknown provider');
  if(!configured(provider)) return oauthError(res, provider, 'OAuth credentials are missing.');
  const state=rand();
  const returnTo=escRedirect(req.query.returnTo || '/');
  states.set(state,{returnTo,created:Date.now()});
  setTimeout(()=>states.delete(state),10*60*1000);
  setCookie(res,'wd_oauth_state',state,600);

  if(provider==='google'){
    const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');
    u.searchParams.set('client_id',env('GOOGLE_CLIENT_ID'));
    u.searchParams.set('redirect_uri',BASE_URL+'/auth/google/callback');
    u.searchParams.set('response_type','code');
    u.searchParams.set('scope','openid email profile');
    u.searchParams.set('access_type','online');
    u.searchParams.set('prompt','select_account');
    u.searchParams.set('state',state);
    return res.redirect(u.toString());
  }
  if(provider==='github'){
    const u=new URL('https://github.com/login/oauth/authorize');
    u.searchParams.set('client_id',env('GITHUB_CLIENT_ID'));
    u.searchParams.set('redirect_uri',BASE_URL+'/auth/github/callback');
    u.searchParams.set('scope','read:user user:email');
    u.searchParams.set('state',state);
    u.searchParams.set('prompt','select_account');
    return res.redirect(u.toString());
  }
  const u=new URL('https://appleid.apple.com/auth/authorize');
  u.searchParams.set('client_id',env('APPLE_CLIENT_ID'));
  u.searchParams.set('redirect_uri',BASE_URL+'/auth/apple/callback');
  u.searchParams.set('response_type','code id_token');
  u.searchParams.set('response_mode','form_post');
  u.searchParams.set('scope','name email');
  u.searchParams.set('state',state);
  return res.redirect(u.toString());
});

async function googleCallback(req,res){
  const code=req.query.code, state=req.query.state;
  const s=states.get(state); states.delete(state);
  if(!s) return res.status(400).send('Invalid or expired OAuth state');
  const tokenRes=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:env('GOOGLE_CLIENT_ID'),client_secret:env('GOOGLE_CLIENT_SECRET'),redirect_uri:BASE_URL+'/auth/google/callback',grant_type:'authorization_code'})});
  if(!tokenRes.ok) return res.status(502).send('Google token exchange failed');
  const tok=await tokenRes.json();
  const me=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:`Bearer ${tok.access_token}`}});
  if(!me.ok) return res.status(502).send('Google profile lookup failed');
  const p=await me.json();
  finishLogin(res,s.returnTo,{provider:'google',id:p.sub,name:p.name||p.email,email:p.email||'',avatar:p.picture||''});
}
app.get('/auth/google/callback', async (req,res)=>{try{await googleCallback(req,res);}catch(e){res.status(500).send('Google sign-in failed');}});

app.get('/auth/github/callback', async (req,res)=>{
  try{
    const state=req.query.state, code=req.query.code; const s=states.get(state); states.delete(state);
    if(!s) return res.status(400).send('Invalid or expired OAuth state');
    const tr=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:env('GITHUB_CLIENT_ID'),client_secret:env('GITHUB_CLIENT_SECRET'),code,redirect_uri:BASE_URL+'/auth/github/callback'})});
    if(!tr.ok) return res.status(502).send('GitHub token exchange failed');
    const tok=await tr.json(); if(!tok.access_token) return res.status(502).send('GitHub did not return an access token');
    const gh=await fetch('https://api.github.com/user',{headers:{Authorization:`Bearer ${tok.access_token}`,Accept:'application/vnd.github+json','User-Agent':'WHITE-DEVIL'}});
    const p=await gh.json();
    const er=await fetch('https://api.github.com/user/emails',{headers:{Authorization:`Bearer ${tok.access_token}`,Accept:'application/vnd.github+json','User-Agent':'WHITE-DEVIL'}});
    const emails=er.ok?await er.json():[];
    const primary=emails.find(x=>x.primary&&x.verified)||emails.find(x=>x.verified)||emails[0];
    finishLogin(res,s.returnTo,{provider:'github',id:String(p.id),name:p.name||p.login,email:(primary&&primary.email)||'',avatar:p.avatar_url||''});
  }catch(e){res.status(500).send('GitHub sign-in failed');}
});

function appleClientSecret(){
  const header=b64u(JSON.stringify({alg:'ES256',kid:env('APPLE_KEY_ID'),typ:'JWT'}));
  const now=Math.floor(Date.now()/1000);
  const payload=b64u(JSON.stringify({iss:env('APPLE_TEAM_ID'),iat:now,exp:now+86400*180,aud:'https://appleid.apple.com',sub:env('APPLE_CLIENT_ID')}));
  const data=Buffer.from(`${header}.${payload}`);
  const sig=crypto.sign('sha256',data,{key:env('APPLE_PRIVATE_KEY').replace(/\\n/g,'\n'),dsaEncoding:'ieee-p1363'});
  return `${header}.${payload}.${sig.toString('base64url')}`;
}
app.post('/auth/apple/callback', async (req,res)=>{
  try{
    const state=req.body.state; const s=states.get(state); states.delete(state);
    if(!s) return res.status(400).send('Invalid or expired OAuth state');
    const tr=await fetch('https://appleid.apple.com/auth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:env('APPLE_CLIENT_ID'),client_secret:appleClientSecret(),code:req.body.code||'',grant_type:'authorization_code',redirect_uri:BASE_URL+'/auth/apple/callback'})});
    if(!tr.ok) return res.status(502).send('Apple token exchange failed');
    const tok=await tr.json();
    const parts=String(tok.id_token||'').split('.');
    if(parts.length!==3) return res.status(502).send('Apple did not return a valid identity token');
    const p=JSON.parse(Buffer.from(parts[1],'base64url').toString());
    finishLogin(res,s.returnTo,{provider:'apple',id:p.sub,name:(req.body.user&&JSON.parse(req.body.user).name?.firstName)||p.email||'Apple User',email:p.email||'',avatar:''});
  }catch(e){res.status(500).send('Apple sign-in failed');}
});

function finishLogin(res,returnTo,profile){
  const sid=rand(24); sessions.set(sid,{profile,created:Date.now()});
  setCookie(res,'wd_oauth_session',sid,60*60*24*7);
  res.redirect(returnTo || '/');
}
app.get('/auth/me',(req,res)=>{
  const sid=cookies(req).wd_oauth_session; const s=sessions.get(sid);
  if(!s) return res.status(401).json({authenticated:false});
  res.json({authenticated:true,user:s.profile});
});
app.post('/auth/logout',(req,res)=>{const sid=cookies(req).wd_oauth_session;sessions.delete(sid);setCookie(res,'wd_oauth_session','',0);res.json({ok:true});});

app.listen(PORT,()=>console.log(`WHITE DEVIL server running at ${BASE_URL}`));
