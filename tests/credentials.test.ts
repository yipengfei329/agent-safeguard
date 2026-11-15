import {test,expect} from 'claude-code/testing';

function setup(on){
  on('fs.exists',()=>({value:false}));
  on('command.register',()=>({value:undefined}));
  on('session.start',()=>({cwd:'/work'}));
  on('turn.start',($,e)=>({turnId:e.turnId}));
  on('turn.abort',()=>({value:undefined}));
}
const source='src/fake.go:21:case "ask", "ask-secret":\nsrc/fake.go:26:item := Question{Secret: cmd == "ask-secret"}';
async function step($){
  const iterator=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});
  let r=await iterator.next();while(!r.done)r=await iterator.next();
}
test('grep command label and boolean expression reach next model step',async($,on)=>{
  setup(on);let calls=0;
  on('tool.call',()=>({result:{stdout:source,stderr:''}}));
  on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
  await $.session.start({cwd:'/work',surface:null,isInteractive:false});
  await $.turn.start({turnId:'t',text:'probe'});
  const r=await $.tool.call({tool:'Bash',command:'read fixture'});
  expect(r.result.stdout).toBe(source);await step($);expect(calls).toBe(1);
});
test('real secret adjacent to allowed code stops the next model step',async($,on)=>{
  setup(on);let calls=0;
  on('tool.call',()=>({result:{stdout:source,stderr:'password=SYNTHETIC_PASSWORD'}}));
  on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
  await $.session.start({cwd:'/work',surface:null,isInteractive:false});
  await $.turn.start({turnId:'t',text:'probe'});
  expect((await $.tool.call({tool:'Bash',command:'read fixture'})).deny).toBe('SAFEGUARD_BLOCKED');
  await step($);expect(calls).toBe(0);
});
test('code-looking structured values need concrete secret evidence',async($,on)=>{
  setup(on);on('tool.call',()=>({result:{token:'config.token'}}));
  await $.session.start({cwd:'/work',surface:null,isInteractive:false});
  expect((await $.tool.call({tool:'mcp__fixture__read'})).result.token).toBe('config.token');
});
test('source references pass through prompt and tool input',async($,on)=>{
  setup(on);on('prompt.submit',($,e)=>({text:e.text}));on('tool.call',()=>({result:'ok'}));
  await $.session.start({cwd:'/work',surface:null,isInteractive:false});
  const text='const token = config.token; self.password = os.environ.get("PASSWORD")';
  expect((await $.prompt.submit({text})).drop).toBeUndefined();
  expect((await $.tool.call({tool:'Bash',command:text})).result).toBe('ok');
});
test('Rust Edit metadata and a test-mode token pass to the next model step',async($,on)=>{
 setup(on);let calls=0;
 const source='pub(crate) api_key: Option<String>,\npub token: std::sync::Arc<SecretString>,\nApp/Push.swift:23: if token == nil, arguments.contains("-SyntheticTestApprove") { token = "simulator" }';
 on('tool.call',()=>({result:{filePath:'/synthetic/api.rs',originalFile:source,structuredPatch:[{lines:['+pub api_key: String,']}]}}));
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'probe'});
 expect((await $.tool.call({tool:'Edit',file_path:'/synthetic/api.rs'})).result.originalFile).toBe(source);await step($);expect(calls).toBe(1);
});
test('a real-looking value next to a Rust declaration still withholds the result',async($,on)=>{
 setup(on);on('tool.call',()=>({result:{originalFile:'pub api_key: String,\nlet token: Option<String> = Some("rQ7!mL2_zA9#vC4-pF8@tN6".into());'}}));
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});expect((await $.tool.call({tool:'Edit',file_path:'/synthetic/api.rs'})).deny).toBe('SAFEGUARD_BLOCKED');
});
test('native dense Rust declarations remain below the inspection budget', {timeoutMs:30000},async($,on)=>{
 setup(on);let output='';on('tool.call',()=>({result:{originalFile:output}}));await $.session.start({cwd:'/work',surface:null,isInteractive:false});
 for(const bytes of [102400,1048576]){
  const line='pub api_key: String,\npub(crate) token: Option<Vec<String>>,\n';output=line.repeat(Math.floor(bytes/line.length)).padEnd(bytes,' ');const samples=[];
  for(let i=0;i<25;i++){const start=Date.now();const r=await $.tool.call({tool:'Edit',file_path:'/synthetic/types.rs'});expect(r.result.originalFile.length).toBe(bytes);if(i>=5)samples.push(Date.now()-start);}
  samples.sort((a,b)=>a-b);console.log(JSON.stringify({scope:'native-rust-types',bytes,rules:6,concurrency:1,p50:samples[9],p95:samples[18],p99:samples[19]}));
 }
});
