import {readFileSync,writeFileSync,renameSync,mkdirSync,existsSync,copyFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {fileURLToPath} from 'node:url';import {resolve,dirname} from 'node:path';import {compile,migrateRules} from '../dist/core.js';
import {collectLocalIdentity,syncLocalIdentityConfig} from '../src/local-identity.js';
const root=fileURLToPath(new URL('..',import.meta.url)),user=process.argv.includes('--user'),plugin=resolve(homedir(),'.local/share/agent-safeguard/marketplace/plugins/agent-safeguard'),dir=user?resolve(plugin,'local'):resolve(root,'local'),target=resolve(dir,'rules.json'),backup=resolve(dir,'rules.previous.json');
const read=path=>{const bytes=readFileSync(path);if(bytes.length>1048576)throw Error();const c=JSON.parse(bytes);compile(c);return c;};
try {
 const args=process.argv.slice(2).filter(a=>a!=='--user');const [action,path,destination]=args;
 if(action==='migrate'){
  if(!path||!destination||destination.startsWith('--'))throw Error();
  const selected=args.indexOf('--redact');const redactIds=selected<0?[]:(args[selected+1]||'').split(',').filter(Boolean);
  const original=read(resolve(path)),config=migrateRules(original,{redactIds});compile(config);
  // Generate a private reviewable draft, never overwrite/apply it implicitly.
  const output=resolve(destination);mkdirSync(dirname(output),{recursive:true,mode:0o700});writeFileSync(output,JSON.stringify(config,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log(JSON.stringify({ok:true,activation:'draft-only',schemaVersion:2,recovery:config.policy.recovery,redactRules:redactIds.length,rulesBefore:original.rules.length,rulesAfter:config.rules.length}));
 }else if(action==='sync-local'){
  if(!path||!destination||destination.startsWith('--'))throw Error();
  const original=read(resolve(path)),values=collectLocalIdentity();
  const config=syncLocalIdentityConfig(original,values);compile(config);
  const output=resolve(destination);mkdirSync(dirname(output),{recursive:true,mode:0o700});writeFileSync(output,JSON.stringify(config,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log(JSON.stringify({ok:true,activation:'draft-only',syncedCount:config.rules.find(r=>r.id==='personal.local-identity').detector.values.length,rulesBefore:original.rules.length,rulesAfter:config.rules.length}));
 }else{
  if(!['validate','apply','rollback'].includes(action))throw Error();
  const source=action==='rollback'?backup:resolve(path),config=read(source),engine=compile(config);
  if(action!=='validate'){
   if(user&&config.schemaVersion===2){const manifest=JSON.parse(readFileSync(resolve(plugin,'.claude-plugin/plugin.json'),'utf8'));const [major,minor]=manifest.version.split('.').map(Number);if(!(major>0||minor>=2))throw Error();}
   mkdirSync(dir,{recursive:true,mode:0o700});
   const temp=resolve(dir,'rules.pending.json');writeFileSync(temp,JSON.stringify(config,null,2)+'\n',{mode:0o600});
   if(existsSync(target))copyFileSync(target,backup);renameSync(temp,target);
  }
  console.log(JSON.stringify({ok:true,version:engine.version,activation:action==='validate'?'validation-only':'new-session-required'}));
 }
}catch{console.error('RULE_CONFIG_REJECTED: validate <file> | migrate <file> <new-draft> [--redact id,id] | sync-local <file> <new-draft> | apply <file> | rollback; v2 user apply requires an updated installation');process.exitCode=1;}
