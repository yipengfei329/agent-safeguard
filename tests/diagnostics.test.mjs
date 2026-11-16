import test from 'node:test';import assert from 'node:assert/strict';
import {diagnosticCause,nextAction,refusal,safeRule,safeReason} from '../src/diagnostics.js';
const base={ready:true,modern:true,blocked:true,recovery:{canResume:true},admission:{},barrier:{}};
const cases=[
 [{},'safe-message'],[{ended:true},'restart'],[{modern:false},'restart'],[{ready:false},'health-check'],[{ready:false,blocked:false},'initializing'],
 [{barrier:{contextBlocked:true},admission:{activeTurns:1}},'fix-context-restart'],[{admission:{submitting:true}},'wait-submission'],
 ...['activeTurns','activeAgents'].map(k=>[{admission:{[k]:1}},'wait-work']),[{recovery:{inFlight:1}},'wait-work'],
 [{barrier:{hard:true}},'health-check'],[{barrier:{hard:true,timeout:true}},'safe-message-probe'],[{blocked:false},'continue'],
];
for(const [overrides,action] of cases)test('recovery advice '+JSON.stringify(overrides),()=>assert.equal(nextAction({...base,...overrides}),action));
test('custom diagnostic content never crosses the boundary',()=>{
 const secret='SYNTHETIC_PRIVATE_VALUE';const c=diagnosticCause(secret,secret,secret,secret);
 assert.deepEqual(c,{rule:'custom.rule',reason:'rule.match',event:'tool.call',tool:null});
 assert(!refusal({effect:'unknown',cause:c,action:'health-check'}).includes(secret));assert.equal(safeRule(null),null);assert.equal(safeReason(secret),'rule.match');
});
for(const effect of ['input','result','unknown','spawn','spawn-result'])test('follow-on effect is independent of original cause: '+effect,()=>{
 const cause=diagnosticCause('security.credentials','url-password','tool.input','Write');const r=refusal({effect,cause,action:'wait-work',related:true});
 assert(r.includes('[session.paused]'));assert(r.includes('Earlier pause: security.credentials / url-password at tool.input (Write)'));assert(r.includes('not replayed'));
 if(effect==='result')assert(r.includes('Tool ran; its result was withheld.'));
 if(effect==='input')assert(r.includes('Tool not executed.'));
 if(effect==='unknown')assert(!r.includes('Tool not executed.'));
});
for(const rule of ['inspection.failed','initialization.failed','tool.hook.failed','prompt.hook.failed','context.hook.failed'])test('fault is not described as a rule match: '+rule,()=>assert.equal(diagnosticCause(rule,null,'tool.call').reason,rule));
