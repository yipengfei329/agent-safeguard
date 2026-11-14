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
test('code-looking structured credential data stays blocked',async($,on)=>{
  setup(on);on('tool.call',()=>({result:{token:'config.token'}}));
  await $.session.start({cwd:'/work',surface:null,isInteractive:false});
  expect((await $.tool.call({tool:'mcp__fixture__read'})).deny).toBe('SAFEGUARD_BLOCKED');
});
test('source references pass through prompt and tool input',async($,on)=>{
  setup(on);on('prompt.submit',($,e)=>({text:e.text}));on('tool.call',()=>({result:'ok'}));
  await $.session.start({cwd:'/work',surface:null,isInteractive:false});
  const text='const token = config.token; self.password = os.environ.get("PASSWORD")';
  expect((await $.prompt.submit({text})).drop).toBeUndefined();
  expect((await $.tool.call({tool:'Bash',command:text})).result).toBe('ok');
});
