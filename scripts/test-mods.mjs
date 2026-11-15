// Each native test file launches an engine. Run files serially so independent
// latency workloads do not compete for the same 100 ms wall-clock budget.
// The tests themselves still exercise concurrent tool calls (including four-way).
import {mkdtempSync,mkdirSync,cpSync,copyFileSync,readdirSync,unlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join} from 'node:path';
import {fileURLToPath} from 'node:url';import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('..',import.meta.url));
const dir=mkdtempSync(join(tmpdir(),'safeguard-mods-'));let failed=0;
try{
 for(const path of ['hooks','.claude-plugin','fixtures','dist'])cpSync(join(root,path),join(dir,path),{recursive:true});
 mkdirSync(join(dir,'tests'));
 for(const file of readdirSync(join(root,'tests')).filter(f=>/\.test\.tsx?$/.test(f)).sort()){
  const target=join(dir,'tests',file);copyFileSync(join(root,'tests',file),target);
  const result=spawnSync('claude',['plugin','test',dir],{stdio:'inherit'});
  if(result.status!==0)failed++;unlinkSync(target);
 }
 console.log(JSON.stringify({scope:'native-suite',mode:'serial-files',failedFiles:failed}));process.exitCode=failed?1:0;
}finally{rmSync(dir,{recursive:true,force:true});}
