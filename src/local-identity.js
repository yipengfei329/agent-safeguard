import os from 'node:os';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import ipaddr from 'ipaddr.js';

const skippedNames=/^(?:localhost|localhost\.localdomain|broadcasthost|ip6-localhost|ip6-loopback|default|unknown|none|unset|local|macbook|imac|mac|ubuntu|debian|fedora|arch|linux|windows|desktop|laptop)$/i;
const reservedMac=/^(?:00(?::00){5}|ff(?::ff){5}|01:00:5e(?::[0-9a-f]{2}){3}|33:33(?::[0-9a-f]{2}){4}|00:00:5e:00:53:[0-9a-f]{2})$/i;

function defaultExec(cmd,args){
  return execFileSync(cmd,args,{encoding:'utf8',timeout:3000,stdio:['ignore','pipe','ignore']});
}

function addCandidate(map,raw){
  if(typeof raw!=='string')return;
  const value=raw.trim();
  if(value.length<3||value.length>256||skippedNames.test(value))return;
  const bare=value.startsWith('[')&&value.endsWith(']')?value.slice(1,-1):value;
  if(ipaddr.isValid(bare)||/^(?:[\w-]+\.)*(?:localhost|example|example\.(?:com|org|net)|test)\.?$/i.test(value))return;
  const lower=value.toLowerCase();
  if(!map.has(lower)&&map.size<128)map.set(lower,value);
}

// Offline local machine fingerprint collection. Never logged or sent anywhere;
// callers write results only to 0600 private rule files.
export function collectLocalIdentity(deps={}){
  const platform=deps.platform??os.platform();
  const getHostname=deps.hostname??os.hostname;
  const getInterfaces=deps.networkInterfaces??os.networkInterfaces;
  const exec=deps.exec??defaultExec;
  const read=deps.readFile??(p=>readFileSync(p,'utf8'));
  const found=new Map();

  try{
    const host=getHostname();
    addCandidate(found,host);
    if(typeof host==='string'&&host.toLowerCase().endsWith('.local'))addCandidate(found,host.slice(0,-6));
  }catch{}

  try{
    const interfaces=getInterfaces()||{};
    for(const list of Object.values(interfaces)){
      for(const item of list||[]){
        if(!item||item.internal||typeof item.mac!=='string')continue;
        const colon=item.mac.trim().toLowerCase().replaceAll('-',':');
        if(!/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/.test(colon)||reservedMac.test(colon))continue;
        addCandidate(found,colon);
        addCandidate(found,colon.replaceAll(':','-'));
      }
    }
  }catch{}

  if(platform==='darwin'){
    for(const key of ['ComputerName','LocalHostName','HostName']){
      try{addCandidate(found,exec('scutil',['--get',key]));}catch{}
    }
    try{
      const ioreg=exec('ioreg',['-rd1','-c','IOPlatformExpertDevice']);
      const serial=ioreg.match(/"IOPlatformSerialNumber"\s*=\s*"([^"]+)"/)?.[1];
      const uuid=ioreg.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/)?.[1];
      addCandidate(found,serial);
      addCandidate(found,uuid);
    }catch{}
  }else if(platform==='linux'){
    try{addCandidate(found,read('/etc/machine-id'));}catch{}
  }

  return [...found.values()];
}

export function syncLocalIdentityConfig(config,values,{disableGenericEnvironment=true}={}){
  if(!Array.isArray(values)||!values.length)throw Error('EMPTY_LOCAL_IDENTITY');
  const map=new Map();
  for(const v of values)addCandidate(map,v);
  const clean=[...map.values()];
  if(!clean.length)throw Error('EMPTY_LOCAL_IDENTITY');
  const out=JSON.parse(JSON.stringify(config));
  const sources=['tool.input','tool.result','user.prompt'];
  if(out.rules.some(r=>r.sources.includes('prompt.context')))sources.push('prompt.context');
  const rule={
    id:'personal.local-identity',
    enabled:true,
    sources,
    action:'block',
    detector:{kind:'exact',values:clean,caseSensitive:false},
  };
  const index=out.rules.findIndex(r=>r.id==='personal.local-identity');
  if(index>=0)out.rules[index]=rule;
  else out.rules.unshift(rule);
  if(disableGenericEnvironment){
    const envRule=out.rules.find(r=>r.id==='identity.environment'&&r.detector?.kind==='builtin'&&r.detector?.name==='personal-environment');
    if(envRule)envRule.enabled=false;
  }
  out.ruleSetVersion=('local-'+out.ruleSetVersion).slice(0,80);
  return out;
}
