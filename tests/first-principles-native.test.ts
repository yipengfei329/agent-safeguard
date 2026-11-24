import {test,expect} from 'claude-code/testing';
import {defaults,migrateRules} from '../dist/core.js';

function modernConfig(){
  const c=migrateRules(defaults,{redactIds:['network.address']});
  for(const r of c.rules){
    r.sources=r.sources.filter(s=>s!=='prompt.context');
    if(r.id==='security.credentials')r.sources=['tool.result','user.prompt'];
    if(r.id==='identity.environment')r.enabled=false;
    if(r.detector.kind==='ip'){
      r.detector.mode='any';
      delete r.detector.country;
      delete r.detector.onUnknown;
      delete r.detector.cidrs;
    }
  }
  return c;
}

function setup(on,config=modernConfig()){
  on('fs.exists',($,e)=>({value:!e.path.endsWith('desktop.json')}));
  on('fs.read',()=>({value:JSON.stringify(config)}));
  on('command.register',()=>({value:undefined}));
  on('session.start',()=>({cwd:'/synthetic'}));
  on('turn.start',($,e)=>({turnId:e.turnId}));
  on('turn.complete',()=>({text:''}));
  on('turn.abort',()=>({value:undefined}));
  on('prompt.submit',($,e)=>({text:e.text}));
}

async function start($){
  await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
}

async function step($,id='t'){
  const it=$.turn.step({turnId:id,index:1,model:'test',messageCount:2});
  let r=await it.next();
  while(!r.done)r=await it.next();
  return r.value;
}

test('Schema 2 allows model-authored mock tokens in Write input while blocking inbound secret results',async($,on)=>{
  setup(on);
  let writes=0,dispatches=0;
  on('tool.call',($,e)=>{
    if(e.tool==='Write'){writes++;return {result:'written'};}
    return {result:{stdout:'api_key="sY9!nT4_hE7#tI2-cK8"',stderr:''}};
  });
  on('turn.step',async function*(){
    dispatches++;
    return {turnId:'t',index:1,answer:'ok',toolUses:[],stopReason:'end_turn',usage:null};
  });
  await start($);
  await $.turn.start({turnId:'t',text:'write test'});
  const w=await $.tool.call({tool:'Write',file_path:'/synthetic/test.ts',content:'const mockToken = "sY9!nT4_hE7#tI2-cK8";'});
  expect(w.deny).toBeUndefined();
  expect(writes).toBe(1);
  await step($);
  expect(dispatches).toBe(1);

  const read=await $.tool.call({tool:'Bash',command:'cat .env'});
  expect(read.deny).toContain('SAFEGUARD_BLOCKED');
  expect(read.deny).toContain('security.credentials');
});

test('active redacted [IP_n] label is blocked from tool.input writeback without false-triggering prior code',async($,on)=>{
  setup(on);
  let executed=0;
  on('tool.call',($,e)=>{
    executed++;
    if(e.tool==='Bash'&&e.command==='diag'){
      return {ref:9,result:{stdout:'2026/01/15 12:00:00 dial tcp 203.0.113.17:443: i/o timeout\n    testing.tRunner(0x1, {0x2})',stderr:'',interrupted:false},text:'raw'};
    }
    return {result:'ok'};
  });
  await start($);
  await $.turn.start({turnId:'t',text:'run'});

  // Before any IP is redacted, editing code referencing "[IP_1]" succeeds.
  const pre=await $.tool.call({tool:'Write',file_path:'/synthetic/spec.ts',content:'expect(out).toContain("[IP_1]")'});
  expect(pre.deny).toBeUndefined();
  expect(executed).toBe(1);

  // Mixed Go standard log + stack braces redacts cleanly without pausing.
  const diag=await $.tool.call({tool:'Bash',command:'diag'});
  expect(diag.deny).toBeUndefined();
  expect(diag.result.stdout).toContain('[IP_1]:443');
  expect(diag.result.stdout).not.toContain('203.0.113.17');
  expect(executed).toBe(2);

  // Subsequent attempt to write or connect to [IP_1] is refused before execution!
  const writeback=await $.tool.call({tool:'Write',file_path:'/synthetic/config.yaml',content:'endpoint: http://[IP_1]:443'});
  expect(writeback.deny).toContain('[redaction.placeholder-input]');
  expect(writeback.deny).toContain('Tool not executed.');
  expect(executed).toBe(2);
});

test('common code identifiers, short hex fingerprints, localhost, and UI password notices pass native dispatch',async($,on)=>{
  setup(on);
  let dispatches=0;
  const polyglot=[
    'const DEFAULT_SECRET = "USER_PROFILE";',
    'const header = { token: "id-verification", secret: "User_Profile" };',
    '<assemblyIdentity name="Synthetic" publicKeyToken="6595b64144ccf1df" />',
    '{"publicKeyToken":"6595b64144ccf1df","password":"Your password expired 3 days ago!"}',
    '{"hostname":"localhost","bind":{"hostname":"127.0.0.1"},"device_id":"device-1"}',
    'ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff',
  ].join('\n');
  on('tool.call',()=>({result:{stdout:polyglot,stderr:''}}));
  on('turn.step',async function*(){
    dispatches++;
    return {turnId:'t',index:1,answer:'ok',toolUses:[],stopReason:'end_turn',usage:null};
  });
  await start($);
  await $.turn.start({turnId:'t',text:'inspect'});
  const r=await $.tool.call({tool:'Bash',command:'inspect'});
  expect(r.deny).toBeUndefined();
  expect(r.result.stdout).toBe(polyglot);
  await step($);
  expect(dispatches).toBe(1);
});
