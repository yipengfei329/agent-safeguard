import {compile,defaults} from '../dist/core.js';
// Desktop bridge config is installed locally with the plugin. Detection never waits
// for reports; the desktop is not part of the decision path.
async function desktopConfig($) {
  const path=$.plugin.root+'/local/desktop.json';
  if(!(await $.fs.exists(path)))return null;
  const raw=await $.fs.read(path,{length:8193});
  if(raw.length>8192)throw Error('BRIDGE_CONFIG');
  const c=JSON.parse(raw);
  if(c.schema!==1||typeof c.rulesPath!=='string'||typeof c.statusDir!=='string')throw Error('BRIDGE_CONFIG');
  return c;
}
function label(value, limit=160) {
  return typeof value==='string'?value.slice(0,limit).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,' ').replace(/[\ud800-\udbff]$/,'').trim():null;
}
async function startReports($, snapshot, lifecycle) {
  try {
    const c=await desktopConfig($);if(!c)return;
    const id=crypto.randomUUID();let sequence=0,inFlight=false,lastWrite=0,dirty=true,eventWritten=false,urgentQueued=false;
    const publish=async()=>{
      if(inFlight||(!dirty&&Date.now()-lastWrite<15000))return;
      inFlight=true;dirty=false;
      const state=snapshot(),now=Date.now();let succeeded=false;
      const row={schema:2,session:id,sequence:++sequence,updatedAt:now,...state};
      try {
        if(state.interception&&!eventWritten){await $.fs.write(c.statusDir+'/interceptions/'+id+'.json',JSON.stringify(row));eventWritten=true;}
        await $.fs.write(c.statusDir+'/'+id+'.json',JSON.stringify(row));lastWrite=now;succeeded=true;
      }catch{dirty=true;}finally{inFlight=false;}
      // A block or final state queued behind a successful write gets a prompt flush.
      if(dirty&&succeeded&&(lifecycle.ended||snapshot().interception))void publish();
    };
    lifecycle.publish=(urgent=false)=>{
      dirty=true;
      if(urgent&&!eventWritten&&!urgentQueued){
        urgentQueued=true;
        try{$.clock.after(0,()=>{urgentQueued=false;void publish();});}catch{urgentQueued=false;}
      }
    };
    lifecycle.timer=$.clock.every(1000,()=>{void publish();});
    lifecycle.finish=()=>{dirty=true;lifecycle.timer.cancel();void publish();};
    // Metadata lookup is background work, never awaited by detection hooks.
    void Promise.allSettled([$.session.id(),$.session.root(),$.session.model()]).then(values=>{
      for(const [i,key] of ['hostSessionId','project','model'].entries()){
        if(values[i].status==='fulfilled'&&!lifecycle.identity[key])lifecycle.identity[key]=label(values[i].value,key==='project'?512:80);
      }
      dirty=true;
    });
    void publish();
    if(lifecycle.ended)lifecycle.finish();
  } catch { /* Observability failure never changes a detection decision. */ }
}
async function loadEngine($) {
  const bridge=await desktopConfig($);
  const path = bridge?.rulesPath || $.plugin.root + '/local/rules.json';
  if (!(await $.fs.exists(path))) {
    if (bridge) throw Error('BRIDGE_RULES_MISSING');
    return compile(defaults);
  }
  const raw = await $.fs.read(path, {length:1048577});
  if (new TextEncoder().encode(raw).length > 1048576) throw Error('CONFIG_LIMIT');
  return compile(JSON.parse(raw));
}
export function register(on){
  let engine={version:defaults.ruleSetVersion,geoip:null},ready=false,blocked=false,turnId=null,lastRule=null,lastReason=null,initializing=null,lastEvent=null;const observed=new Set();
  const lifecycle={ended:false,timer:null,finish:null,identity:{agent:'Claude Code',hostSessionId:null,title:null,project:null,model:null,agentType:null}};let reporting=false,finalDecision=null,interception=null;const actors=new Map();
  const report=()=>({identity:lifecycle.identity,interception,pluginVersion:'0.1.24',ready,blocked,ended:lifecycle.ended,lastEvent:finalDecision?.event||lastEvent,ruleVersion:engine.version,lastRule:(finalDecision?.rule||lastRule)&&(['network.address','identity.device','identity.environment','security.credentials','inspection.failed','initialization.failed','prompt.hook.failed','context.hook.failed','session.ended','tool.hook.failed'].includes(finalDecision?.rule||lastRule)?(finalDecision?.rule||lastRule):'custom.rule')});
  function capture(rule,event,tool,agentId){
    if(interception)return;
    interception={at:Date.now(),ruleId:label(rule,80),event,tool:label(tool,80),agentId:label(agentId,80),agentType:actors.get(agentId)||null,identity:{...lifecycle.identity}};
  }
  function inspect(value,source,tool,agentId){const r=engine.scan(value,source,tool);if(r.blocked){lastRule=r.rule;lastReason=r.reason||null;lastEvent=source;capture(r.rule,source,tool,agentId);}for(const id of r.observed||[])observed.add(id);return r;}
  function fail(rule,event){blocked=true;lastRule=rule;lastReason=null;lastEvent=event;capture(rule,event);notify();}
  // Existing host events supply identity; no transcript scan or title generation.
  on('classic.SessionStart',($,e,next)=>{Object.assign(lifecycle.identity,{hostSessionId:label(e.session_id,80),project:label(e.cwd,512),title:label(e.session_title),agentType:label(e.agent_type,80),model:label(e.model,80)});notify();return next(e);});
  on('classic.UserPromptSubmit',($,e,next)=>{if(e.session_title)lifecycle.identity.title=label(e.session_title);notify();return next(e);});
  on('classic.CwdChanged',($,e,next)=>{lifecycle.identity.project=label(e.new_cwd,512);notify();return next(e);});
  on('classic.SubagentStart',($,e,next)=>{if(actors.size<64)actors.set(e.agent_id,label(e.agent_type,80));return next(e);});
  const notify=()=>lifecycle.publish?.(interception!==null);
  const deny=()=>({deny:'SAFEGUARD_BLOCKED'});
  on('session.start',async ($,e,next)=>{
    if(!reporting){reporting=true;lifecycle.identity.project=label(e.cwd,512);void startReports($,report,lifecycle);}
    await $.command.register({name:'agent-safeguard-status',description:'Show local safeguard status'});
    engine = await (initializing ??= loadEngine($));
    ready = true;notify();
    return next(e);
  }).catch(()=>{ready=false;fail('initialization.failed','session.start');return {};});
  // Reason codes contain no values. Keep them in the on-demand status only:
  // existing desktop schema-2 readers reject unknown snapshot properties.
  on('command.run',{command:'agent-safeguard-status'},()=>({text:JSON.stringify({pluginVersion:'0.1.24',ready,blocked,lastEvent,ruleVersion:engine.version,geoip:engine.geoip,lastRule,lastReason,observedRules:[...observed],coverage:'experimental-tool-and-context-guard'})}));
  on('turn.start',async ($,e,next)=>{if(!e.agentId)turnId=e.turnId;return next(e);});
  on('tool.call',async ($,e,next)=>{
    if(!ready||blocked)return deny();
    if(inspect(e,'tool.input',e.tool,e.agentId).blocked){blocked=true;notify();if(turnId)await $.turn.abort({turnId});return deny();}
    const result=await next(e);
    if(blocked||inspect(result,'tool.result',e.tool,e.agentId).blocked){blocked=true;notify();if(turnId)await $.turn.abort({turnId});return deny();}
    return result;
  }).catch(()=>{fail('tool.hook.failed','tool.call');return deny();});
  on('turn.step',async function* ($,e,next){
    if(!ready||blocked){yield {kind:'stop',stopReason:'end_turn',usage:null};return {turnId:e.turnId,index:e.index,answer:'',toolUses:[],stopReason:'end_turn',usage:null};}
    return yield* next(e);
  });
  on('prompt.submit',async ($,e,next)=>{
    engine = await (initializing ??= loadEngine($));
    ready = true;notify();
    if(blocked||inspect(e.text,'user.prompt').blocked){
      blocked=true;notify();
      return {drop:'SAFEGUARD_BLOCKED ['+(lastRule||'session.locked')+']; run /agent-safeguard-status'};
    }
    return next(e);
  }).catch(()=>{fail(ready?'prompt.hook.failed':'initialization.failed','prompt.submit');return {drop:'SAFEGUARD_BLOCKED ['+lastRule+']; run /agent-safeguard-status'};});
  on('prompt.section',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;notify();return {text:null};}return r;}).catch(()=>{fail(ready?'context.hook.failed':'initialization.failed','prompt.section');return {text:null};});
  on('prompt.context',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;notify();return {blocks:[]};}return r;}).catch(()=>{fail(ready?'context.hook.failed':'initialization.failed','prompt.context');return {blocks:[]};});
  on('prompt.attachment',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;notify();return {text:null};}return r;}).catch(()=>{fail(ready?'context.hook.failed':'initialization.failed','prompt.attachment');return {text:null};});
  on('agent.spawn',async ($,e,next)=>blocked||!ready?deny():next(e)).catch(()=>{blocked=true;notify();return deny();});
  on('session.compact',async ($,e,next)=>blocked||!ready?{skip:'SAFEGUARD_BLOCKED'}:next(e)).catch(()=>{blocked=true;notify();return {skip:'SAFEGUARD_BLOCKED'};});
  on('session.end',async ($,e,next)=>{if(blocked)finalDecision={rule:lastRule,event:lastEvent};blocked=true;notify();ready=false;lastRule='session.ended';lastReason=null;lastEvent='session.end';lifecycle.ended=true;lifecycle.finish?.();return next(e);});
}
