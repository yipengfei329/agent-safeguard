import {test,expect,mock} from 'claude-code/testing';
import {defaults} from '../dist/core.js';
const config=JSON.parse(JSON.stringify(defaults));
for(const r of config.rules)r.sources=r.sources.filter(s=>s!=='prompt.context');
const bridge={schema:1,rulesPath:'/synthetic/local/rules.json',statusDir:'/synthetic/sessions'};
function setup(on,writes,reads,fail=false,missingRules=false){
 on('fs.exists',($,e)=>({value:!missingRules||e.path!==bridge.rulesPath}));
 on('fs.read',($,e)=>{reads.push(e.path);return {value:JSON.stringify(e.path.endsWith('desktop.json')?bridge:config)};});
 on('fs.write',($,e)=>{writes.push(e);if(fail)return {deny:'SYNTHETIC_PRIVATE_ERROR'};return {value:undefined};});
 on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));on('session.end',()=>({sessionId:'synthetic'}));on('turn.abort',()=>({value:undefined}));
}
test('desktop bridge loads shared rules and reports only metadata',async($,on)=>{
 const clock=mock.clock(on);const writes=[],reads=[];setup(on,writes,reads);on('tool.call',()=>({result:'password=sY9!nT4_hE7#tI2-cK8'}));
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 const r=await $.tool.call({tool:'Bash',command:'fixture'});expect(r.deny).toBe('SAFEGUARD_BLOCKED');
 await clock.advance(1200);
 expect(reads.includes(bridge.rulesPath)).toBe(true);expect(writes.length>0).toBe(true);
 const latest=JSON.parse(writes[writes.length-1].text);expect(latest.blocked).toBe(true);expect(latest.lastRule).toBe('security.credentials');expect(latest.lastEvent).toBe('tool.result');
 expect(JSON.stringify(writes).includes('sY9!nT4_hE7#tI2-cK8')).toBe(false);
});
test('missing desktop rules cannot silently fall back to defaults',async($,on)=>{
 const clock=mock.clock(on);setup(on,[],[],false,true);on('tool.call',()=>({result:'BUILD_OK'}));
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await clock.advance(100);
 expect((await $.tool.call({tool:'Bash',command:'fixture'})).deny).toBe('SAFEGUARD_BLOCKED');
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.ready).toBe(false);expect(status.blocked).toBe(true);
});
test('status transport failure never changes detector return or leaks an error',async($,on)=>{
 const clock=mock.clock(on);const writes=[],reads=[];setup(on,writes,reads,true);on('tool.call',()=>({result:'BUILD_OK'}));
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await clock.advance(100);
 expect((await $.tool.call({tool:'Bash',command:'fixture'})).result).toBe('BUILD_OK');
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.ready).toBe(true);expect(status.blocked).toBe(false);
});
test('overview identity and first interception use host metadata without writing on the scan path',async($,on)=>{
 const clock=mock.clock(on);const writes=[],reads=[];setup(on,writes,reads);
 on('session.id',()=>({value:'00000000-0000-4000-8000-000000000123'}));
 on('session.root',()=>({value:'/synthetic/catalog'}));on('session.model',()=>({value:'synthetic-model'}));
 on('classic.SessionStart',()=>({}));on('classic.UserPromptSubmit',()=>({}));
 on('tool.call',()=>({result:'password=sY9!nT4_hE7#tI2-cK8'}));
 await $.session.start({cwd:'/synthetic/catalog',surface:null,isInteractive:false});
 await $.classic.SessionStart({source:'startup',session_id:'00000000-0000-4000-8000-000000000123',cwd:'/synthetic/catalog',session_title:'修复搜索排序',model:'synthetic-model'});
 await clock.advance(1100);writes.length=0;
 const result=await $.tool.call({tool:'Bash',command:'synthetic fixture'});
 expect(result.deny).toBe('SAFEGUARD_BLOCKED');expect(writes.length).toBe(0);
 await clock.advance(1100);
 const archives=writes.filter(w=>w.path.includes('/interceptions/'));expect(archives.length).toBe(1);
 const row=JSON.parse(archives[0].text);expect(row.schema).toBe(2);expect(row.interception.identity.title).toBe('修复搜索排序');
 expect(row.interception.identity.project).toBe('/synthetic/catalog');expect(row.interception.ruleId).toBe('security.credentials');
 expect(row.interception.tool).toBe('Bash');expect(row.interception.event).toBe('tool.result');expect(row.interception.at>0).toBe(true);
 expect(JSON.stringify(writes).includes('sY9!nT4_hE7#tI2-cK8')).toBe(false);
 await clock.advance(16000);expect(writes.filter(w=>w.path.includes('/interceptions/')).length).toBe(1);
});
test('an unresolved report write cannot hold up a clean tool result',async($,on)=>{
 mock.clock(on);
 on('fs.exists',()=>({value:true}));on('fs.read',($,e)=>({value:JSON.stringify(e.path.endsWith('desktop.json')?bridge:config)}));
 let release;const held=new Promise(resolve=>{release=resolve;});
 on('fs.write',async()=>{await held;return {value:undefined};});
 on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));on('tool.call',()=>({result:'BUILD_OK'}));
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 expect((await $.tool.call({tool:'Bash',command:'fixture'})).result).toBe('BUILD_OK');release();
});
