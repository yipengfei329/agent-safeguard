import {compile} from '../dist/core.js';
import {clean,sensitive,formatProbes} from '../fixtures/credential-corpus.mjs';
import {mkdirSync,mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,basename,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';

const regression=[...clean.map(x=>[...x,false]),...sensitive.map(x=>[...x,true])];
const cases=[...regression,...formatProbes.map(x=>[...x,true])];
const results=[];
function score(name,detected){
  const failures=regression.filter(([id,,,expected])=>detected.has(id)!==expected).map(([id,,,expected])=>({id,expected}));
  results.push({name,clean:clean.length,sensitive:sensitive.length,falsePositives:failures.filter(x=>!x.expected).length,falseNegatives:failures.filter(x=>x.expected).length,failures,formatProbes:{total:formatProbes.length,detected:formatProbes.filter(([id])=>detected.has(id)).length}});
}
function scan(engine){return new Set(cases.filter(([,,text])=>engine.scan(text).blocked).map(([id])=>id));}
if(process.env.SAFEGUARD_BASELINE_MODULE){const baseline=await import(pathToFileURL(resolve(process.env.SAFEGUARD_BASELINE_MODULE)));score('agent-safeguard-before',scan(baseline.compile()));}
score('agent-safeguard-current',scan(compile()));
if(process.env.SAFEGUARD_GITLEAKS||process.env.SAFEGUARD_DETECT_SECRETS){
  const dir=mkdtempSync(join(tmpdir(),'safeguard-synthetic-corpus-'));
  try{
    const fixtureDir=join(dir,'cases');mkdirSync(fixtureDir);
    for(const [id,ext,text] of cases)writeFileSync(join(fixtureDir,id+'.'+ext),text+'\n');
    const env={...process.env};delete env.GITLEAKS_CONFIG;delete env.GITLEAKS_CONFIG_TOML;
    if(process.env.SAFEGUARD_GITLEAKS){
      const report=join(dir,'gitleaks.json');
      const r=spawnSync(resolve(process.env.SAFEGUARD_GITLEAKS),['dir',fixtureDir,'--no-banner','--no-color','--redact','--report-format','json','--report-path',report,'--exit-code','0'],{cwd:dir,env,encoding:'utf8',timeout:60000});
      if(r.status!==0)throw Error('GITLEAKS_COMPARISON_FAILED');
      score('gitleaks-default-offline',new Set(JSON.parse(readFileSync(report,'utf8')).map(x=>basename(x.File).replace(/\.[^.]+$/,''))));
    }
    if(process.env.SAFEGUARD_DETECT_SECRETS){
      const r=spawnSync(resolve(process.env.SAFEGUARD_DETECT_SECRETS),['scan','--all-files','--no-verify',fixtureDir],{cwd:dir,env,encoding:'utf8',timeout:60000});
      if(r.status!==0)throw Error('DETECT_SECRETS_COMPARISON_FAILED');
      score('detect-secrets-default-no-verify',new Set(Object.keys(JSON.parse(r.stdout).results).map(x=>basename(x).replace(/\.[^.]+$/,''))));
    }
  }finally{rmSync(dir,{recursive:true,force:true});}
}
console.log(JSON.stringify({scope:'synthetic-regression-corpus-not-general-accuracy',cases:cases.length,results},null,2));
