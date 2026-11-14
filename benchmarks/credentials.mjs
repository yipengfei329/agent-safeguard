import {compile} from '../dist/core.js';
import {performance} from 'node:perf_hooks';
import {mkdirSync,writeFileSync} from 'node:fs';
const engine=compile(),results=[];
for(const size of [10240,102400,1048576])for(const minified of [false,true]){
  const line='const token = config.token; let secret: Bool = false; opts := Options{Token: config.Token};'+(minified?' ':'\n');
  const output=line.repeat(Math.ceil(size/line.length)),times=[];
  for(let i=0;i<60;i++){
    const start=performance.now(),result=engine.scan({stdout:output,stderr:''});
    if(result.blocked)throw Error(`Unexpected decision: ${result.rule}`);
    if(i>=10)times.push(performance.now()-start);
  }
  times.sort((a,b)=>a-b);
  results.push({bytes:Buffer.byteLength(output),minified,scope:'core-scan',rules:6,concurrency:1,p50:times[24],p95:times[47],p99:times[49]});
}
mkdirSync('benchmarks/results',{recursive:true});
writeFileSync('benchmarks/results/credentials-dense.json',JSON.stringify(results,null,2));
console.log(JSON.stringify(results,null,2));
