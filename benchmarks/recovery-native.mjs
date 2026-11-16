// Measure the full native hook, including input scan, output transform and rescan.
// Synthetic data only; no user rules or credentials.
import {mkdtempSync,mkdirSync,cpSync,copyFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('..',import.meta.url));
const baseline=process.argv.includes('--baseline');
const dir=mkdtempSync(join(tmpdir(),'safeguard-recovery-bench-'));
try{
 for(const path of ['hooks','.claude-plugin','fixtures'])cpSync(join(root,path),join(dir,path),{recursive:true});
 if(baseline)writeFileSync(join(dir,'hooks/register.js'),'export function register() {}\n');
 mkdirSync(join(dir,'dist'));mkdirSync(join(dir,'tests'));
 copyFileSync(join(root,'dist/core.js'),join(dir,'dist/core.js'));
 copyFileSync(join(root,baseline?'benchmarks/recovery-baseline.probe.ts':'benchmarks/recovery-native.probe.ts'),join(dir,'tests/recovery-native.test.ts'));
 const result=spawnSync('claude',['plugin','test',dir],{stdio:'inherit'});
 process.exitCode=result.status??1;
}finally{rmSync(dir,{recursive:true,force:true});}
