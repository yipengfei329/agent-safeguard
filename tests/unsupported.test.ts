import {test,expect} from 'claude-code/testing';
const image={type:'image',source:{type:'base64',media_type:'image/png',data:'AAAA'}};
function setup(on){on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/work'}));on('turn.start',($,e)=>({turnId:e.turnId}));on('turn.abort',()=>({value:undefined}));on('prompt.submit',($,e)=>({text:e.text}));}
test('image result passes and later prompts and model steps stay available',async($,on)=>{
 setup(on);let calls=0;on('tool.call',()=>({result:{content:[image]}}));
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'read screenshot'});
 const r=await $.tool.call({tool:'Read',file_path:'/work/fixture.png'});expect(r.result.content[0].type).toBe('image');
 expect((await $.prompt.submit({text:'Continue'})).drop).toBeUndefined();
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});let step=await it.next();while(!step.done)step=await it.next();expect(calls).toBe(1);
 expect(JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text).blocked).toBe(false);
});
test('image with sensitive text is still withheld',async($,on)=>{
 setup(on);on('tool.call',()=>({result:{content:[image,{type:'text',text:'password=SYNTHETIC_PASSWORD'}]}}));
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});
 expect((await $.tool.call({tool:'Read',file_path:'/work/fixture.png'})).deny).toBe('SAFEGUARD_BLOCKED');
});
