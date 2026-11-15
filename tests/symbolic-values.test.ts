import {test,expect} from 'claude-code/testing';
function setup(on){on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));on('turn.start',($,e)=>({turnId:e.turnId}));on('turn.abort',()=>({value:undefined}));}
const secret='pM8!sQ3_vL7#rD5-tN2@xK9';
for(const [name,output,blocked,error] of [
 ['name-comment','# Repository secret: ORCHARD_PUBLISH_TOKEN (configured externally)',false,false],
 ['name-error','// Required secret: "CINDER_BUILD_KEY"',false,true],
 ['reference',JSON.stringify({token:'secrets["MESA_DEPLOY_TOKEN"]'}),false,false],
 ['github-reference','# token: ${{ secrets.ORCHARD_PUBLISH_TOKEN }}',false,false],
 ['code-reference','const token = ORCHARD_PUBLISH_TOKEN;',false,false],
 ['comment-secret','# secret: '+secret,true,false],
 ['hash-code-comment','# const token = qR7mT2vK9zP4sN8xL3bC6;',true,false],
 ['comment-secret-error','# secret: '+secret,true,true],
 ['declared-secret','# Repository secret: '+secret,true,false],
 ['uppercase-value','# secret: ORCHARD_PUBLISH_TOKEN',true,false],
 ['structured-value',JSON.stringify({secret:'ORCHARD_PUBLISH_TOKEN'}),true,false],
 ['name-adjacent','# Repository secret: ORCHARD_PUBLISH_TOKEN\n# secret: '+secret,true,false],
 ['name-joined','# Repository secret: "ORCHARD_PUBLISH_TOKEN" + "Q7LM2ZP9VN4RX8TC3KB6DS5F"',true,false],
 ['name-cache','# Repository secret: "ORCHARD_PUBLISH_TOKEN"\nsecret="ORCHARD_PUBLISH_TOKEN"',true,false],
 ['indexed-material',JSON.stringify({secret:`secrets['${secret}']`}),true,false],
])test('symbolic value '+name,async($,on)=>{
 setup(on);let calls=0;on('tool.call',()=>({isError:error,result:error?{stderr:output}:{stdout:output}}));
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'probe'});
 const r=await $.tool.call({tool:'Bash',command:'read synthetic fixture'});
 if(blocked){expect(r.deny).toBe('SAFEGUARD_BLOCKED');const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.lastRule).toBe('security.credentials');}
 else{expect(r.deny).toBeUndefined();expect(error?r.result.stderr:r.result.stdout).toBe(output);}
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});while(!(await it.next()).done){}expect(calls).toBe(blocked?0:1);
});
for(const target of ['tool','prompt'])test('symbolic '+target+' input checks adjacent actual values',async($,on)=>{
 setup(on);let calls=0;on('tool.call',()=>{calls++;return {result:'ok'};});on('prompt.submit',($,e)=>{calls++;return {text:e.text};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 const clean='# Repository secret: ORCHARD_PUBLISH_TOKEN',sensitive=clean+'\n# secret: '+secret;
 if(target==='tool'){
  expect((await $.tool.call({tool:'Bash',command:clean})).deny).toBeUndefined();
  expect((await $.tool.call({tool:'Bash',command:sensitive})).deny).toBe('SAFEGUARD_BLOCKED');
 }else{
  expect((await $.prompt.submit({text:clean})).text).toBe(clean);
  expect((await $.prompt.submit({text:sensitive})).drop).toContain('SAFEGUARD_BLOCKED');
 }
 expect(calls).toBe(1);
});
