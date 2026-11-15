// Compare bundled engines through the same native Mods tool-result hook.
// Optional argument: a saved core.js bundle. No user rules or credentials.
import {mkdtempSync,mkdirSync,cpSync,copyFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('..',import.meta.url));
const dir=mkdtempSync(join(tmpdir(),'safeguard-dense-'));
try{
 for(const path of ['hooks','.claude-plugin','fixtures'])cpSync(join(root,path),join(dir,path),{recursive:true});
 mkdirSync(join(dir,'dist'));mkdirSync(join(dir,'tests'));
 copyFileSync(process.argv[2]?resolve(process.argv[2]):join(root,'dist/core.js'),join(dir,'dist/core.js'));
 copyFileSync(join(root,'benchmarks/dense-native.probe.ts'),join(dir,'tests/dense-native.test.ts'));
 const result=spawnSync('claude',['plugin','test',dir],{stdio:'inherit'});
 process.exitCode=result.status??1;
}finally{rmSync(dir,{recursive:true,force:true});}
