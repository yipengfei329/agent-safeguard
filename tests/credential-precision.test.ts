import {test,expect} from 'claude-code/testing';
function setup(on){on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));on('turn.start',($,e)=>({turnId:e.turnId}));on('turn.abort',()=>({value:undefined}));}
const source='interface Options { token: "custom-type-discriminant"; }\nconst password = "Please enter your password";\nconst secret = "AWS_SECRET_ACCESS_KEY";\nconst token = "application/json";\nconst Authorization = "<binding:credential>";';
const secret='rQ7!mL2_zA9#vC4-pF8@tN6';
async function step($){const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});while(!(await it.next()).done){}}
for(const [name,output,blocked,isError] of [
 ['short-prefixed','const TOKEN: &str = "harbour-4n8r2w6s9z";',false,false],
 ['numbered-label','const TOKEN: &str = "lanterns-24680";',false,false],
 ['numbered-error','api_key=meadows_907314',false,true],
 ['numbered-adjacent','token=lanterns-24680\napi_key='+secret,true,false],
 ['numbered-password','password=lanterns-24680',true,false],
 ['code',source,false,false],
 ['error-code',source,false,true],
 ['adjacent',source+'\napi_key='+secret,true,false],
 ['error-secret',source+'\napi_key='+secret,true,true],
 ['comment','interface Options { /* password='+secret+' */ value: string; }',true,false],
 ['regex','function render() { const pattern = /interface Options {/; const x = { token: "'+secret+'" }; }',true,false],
 ['empty-assignment','PASSWORD= HOST=demo-service',false,false],
 ['metadata','token_count=1234567890\naccess_token_expires_at="2026-11-15T12:34:56Z"',false,false],
 ['template-reference','DB_PASSWORD="${DB_PASSWORD}"',false,false],
 ['prefixed-field','DB_PASSWORD="'+secret+'"',true,false],
 ['template-literal','DB_PASSWORD="'+secret+'${SUFFIX}"',true,false],
 ['empty-user-url','redis://:xyz@cache.example.invalid',true,false],
 ['empty-adjacent','PASSWORD= SERVICE_API_TOKEN='+secret,true,false],
 ['prefixed-error','SERVICE_API_TOKEN='+secret,true,true],
 ['syntax-reference','["Authorization": "<binding:credential>"]',false,false],
 ['syntax-reference-error','["Authorization": "[source:session]"]',false,true],
 ['syntax-real-value','["Authorization": "<binding:'+secret+'>"]',true,false],
 ['syntax-adjacent','["Authorization": "<binding:credential>"]\nDB_PASSWORD='+secret,true,false],
])test('precision result '+name,async($,on)=>{
 setup(on);let calls=0;on('tool.call',()=>({isError,result:{stdout:output}}));
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'probe'});
 const r=await $.tool.call({tool:'Bash',command:'read synthetic source'});
 if(blocked)expect(r.deny).toBe('SAFEGUARD_BLOCKED');else expect(r.result.stdout).toBe(output);
 await step($);expect(calls).toBe(blocked?0:1);
});
test('precision prompt and input still enforce adjacent credentials before executing',async($,on)=>{
 setup(on);let calls=0;on('prompt.submit',($,e)=>({text:e.text}));on('tool.call',()=>{calls++;return {result:'ok'};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 expect((await $.prompt.submit({text:source})).text).toBe(source);
 expect((await $.tool.call({tool:'Bash',command:source})).result).toBe('ok');
 expect((await $.tool.call({tool:'Bash',command:source+'\napi_key='+secret})).deny).toBe('SAFEGUARD_BLOCKED');expect(calls).toBe(1);
});
for(const input of ['tool','prompt'])test('prefixed credentials prevent '+input,async($,on)=>{
 setup(on);let calls=0;on('prompt.submit',()=>{calls++;return {text:'submitted'};});on('tool.call',()=>{calls++;return {result:'executed'};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 if(input==='tool')expect((await $.tool.call({tool:'Bash',command:'DB_PASSWORD='+secret})).deny).toBe('SAFEGUARD_BLOCKED');
 else expect((await $.prompt.submit({text:'SERVICE_API_TOKEN='+secret})).drop).toContain('SAFEGUARD_BLOCKED');expect(calls).toBe(0);
});
test('native precision workload latency', {timeoutMs:30000},async($,on)=>{
 setup(on);let output='';on('tool.call',()=>({result:{stdout:output}}));await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 for(const bytes of [10240,102400,1048576])for(const concurrency of [1,4]){
   const line=source+'\n';output=line.repeat(Math.floor(bytes/line.length)).padEnd(bytes,' ');const samples=[];
   for(let i=0;i<25;i++)await Promise.all(Array.from({length:concurrency},async()=>{
     const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'read synthetic source'});expect(r.result.stdout.length).toBe(bytes);if(i>=5)samples.push(Date.now()-start);
   }));
   samples.sort((a,b)=>a-b);const q=p=>samples[Math.min(samples.length-1,Math.ceil(p*samples.length)-1)];
   console.log(JSON.stringify({scope:'native-credential-precision',bytes,rules:6,concurrency,samples:samples.length,p50:q(.5),p95:q(.95),p99:q(.99)}));
 }
});
