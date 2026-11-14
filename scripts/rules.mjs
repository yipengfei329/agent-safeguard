import {readFileSync,writeFileSync,renameSync,mkdirSync,existsSync,copyFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {fileURLToPath} from 'node:url';import {resolve} from 'node:path';import {compile} from '../dist/core.js';
const root=fileURLToPath(new URL('..',import.meta.url)),dir=process.argv.includes('--user')?resolve(homedir(),'.local/share/agent-safeguard/marketplace/plugins/agent-safeguard/local'):resolve(root,'local'),target=resolve(dir,'rules.json'),backup=resolve(dir,'rules.previous.json');
try {
 const [action,path]=process.argv.slice(2).filter(a=>a!=='--user');
 if(!['validate','apply','rollback'].includes(action))throw Error();
 const source=action==='rollback'?backup:resolve(path);
 const bytes=readFileSync(source);if(bytes.length>1048576)throw Error();
 const config=JSON.parse(bytes);const engine=compile(config);
 if(action!=='validate'){
  mkdirSync(dir,{recursive:true,mode:0o700});
  const temp=resolve(dir,'rules.pending.json');writeFileSync(temp,JSON.stringify(config,null,2)+'\n',{mode:0o600});
  if(existsSync(target))copyFileSync(target,backup);
  renameSync(temp,target);
 }
 console.log(JSON.stringify({ok:true,version:engine.version,activation:action==='validate'?'validation-only':'new-session-required'}));
}catch{console.error('RULE_CONFIG_REJECTED: use validate <file>, apply <file>, or rollback');process.exitCode=1;}
