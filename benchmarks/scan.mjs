import {compile} from '../dist/core.js';import {performance} from 'node:perf_hooks';import {mkdirSync,writeFileSync} from 'node:fs';
const e=compile(),results=[];
for(const size of [10240,102400,1048576])for(const hit of [false,true]){const s='build complete\n'.repeat(Math.ceil(size/15)).slice(0,size)+(hit?' 203.0.113.8':'');const times=[];for(let i=0;i<120;i++){const t=performance.now();const r=e.scan({stdout:s,stderr:''});if(r.blocked!==hit)throw Error('Unexpected decision');if(i>=20)times.push(performance.now()-t);}times.sort((a,b)=>a-b);results.push({bytes:size,hit,p50:times[49],p95:times[94],p99:times[98]});}
mkdirSync('benchmarks/results',{recursive:true});writeFileSync('benchmarks/results/scan.json',JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
