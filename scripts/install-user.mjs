import {mkdirSync,copyFileSync,existsSync,writeFileSync,readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {compile} from '../dist/core.js';
const root=fileURLToPath(new URL('..',import.meta.url));
const market=resolve(homedir(),'.local/share/agent-safeguard/marketplace');
const plugin=resolve(market,'plugins/agent-safeguard');
const config=resolve(plugin,'local/rules.json');
mkdirSync(dirname(config),{recursive:true,mode:0o700});
if(!existsSync(config))copyFileSync(resolve(root,'config/tool-results.json'),config);
compile(JSON.parse(readFileSync(config,'utf8')));
for(const file of ['hooks/register.js','hooks/hooks.json','dist/core.js','.claude-plugin/plugin.json','README.md','LICENSE']){
 const dest=resolve(plugin,file);mkdirSync(dirname(dest),{recursive:true});copyFileSync(resolve(root,file),dest);
}
mkdirSync(resolve(market,'.claude-plugin'),{recursive:true});
writeFileSync(resolve(market,'.claude-plugin/marketplace.json'),JSON.stringify({name:'agent-safeguard-local',owner:{name:'Local Agent Safeguard'},plugins:[{name:'agent-safeguard',source:'./plugins/agent-safeguard',description:'Local tool result privacy guard'}]},null,2));
const result=spawnSync('claude',['plugin','install','agent-safeguard','--marketplace',market,'--scope','user','--json'],{stdio:'inherit'});
process.exitCode=result.status??1;
