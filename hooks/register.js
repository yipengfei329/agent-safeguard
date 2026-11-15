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
async function startReports($, snapshot, lifecycle) {
  try {
    const c=await desktopConfig($);if(!c)return;
    const id=crypto.randomUUID();let sequence=0,inFlight=false,last='',lastWrite=0;
    const publish=async()=>{
      if(inFlight)return;
      const state=snapshot(),key=JSON.stringify(state),now=Date.now();
      if(key===last&&now-lastWrite<15000)return;
      inFlight=true;
      try {await $.fs.write(c.statusDir+'/'+id+'.json',JSON.stringify({schema:1,session:id,sequence:++sequence,updatedAt:now,...state}));last=key;lastWrite=now;}catch{}finally{inFlight=false;if(last===key&&JSON.stringify(snapshot())!==last)void publish();}
    };
    lifecycle.publish=()=>{void publish();};
    lifecycle.timer=$.clock.every(1000,()=>{void publish();});
    lifecycle.finish=()=>{lifecycle.timer.cancel();void publish();};
    void publish();
    if(lifecycle.ended)lifecycle.finish();
  } catch { /* A missing/broken status bridge never changes a detection decision. */ }
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
  let engine=compile(defaults),ready=false,blocked=false,turnId=null,lastRule=null,initializing=null,lastEvent=null;const observed=new Set();
  const lifecycle={ended:false,timer:null,finish:null};let reporting=false,finalDecision=null;
  const report=()=>({pluginVersion:'0.1.11',ready,blocked,ended:lifecycle.ended,lastEvent:finalDecision?.event||lastEvent,ruleVersion:engine.version,lastRule:(finalDecision?.rule||lastRule)&&(['network.address','identity.device','identity.environment','security.credentials','inspection.failed','initialization.failed','prompt.hook.failed','context.hook.failed','session.ended','tool.hook.failed'].includes(finalDecision?.rule||lastRule)?(finalDecision?.rule||lastRule):'custom.rule')});
  function inspect(value,source,tool){const r=engine.scan(value,source,tool);if(r.blocked){lastRule=r.rule;lastEvent=source;}for(const id of r.observed||[])observed.add(id);return r;}
  const notify=()=>lifecycle.publish?.();
  const deny=()=>({deny:'SAFEGUARD_BLOCKED'});
  on('session.start',async ($,e,next)=>{
    if(!reporting){reporting=true;void startReports($,report,lifecycle);}
    await $.command.register({name:'agent-safeguard-status',description:'Show local safeguard status'});
    engine = await (initializing ??= loadEngine($));
    ready = true;notify();
    return next(e);
  }).catch(()=>{blocked=true;notify();ready=false;lastRule='initialization.failed';lastEvent='session.start';return {};});
  on('command.run',{command:'agent-safeguard-status'},()=>({text:JSON.stringify({pluginVersion:'0.1.11',ready,blocked,lastEvent,ruleVersion:engine.version,lastRule,observedRules:[...observed],coverage:'experimental-tool-and-context-guard'})}));
  on('turn.start',async ($,e,next)=>{if(!e.agentId)turnId=e.turnId;return next(e);});
  on('tool.call',async ($,e,next)=>{
    if(!ready||blocked)return deny();
    if(inspect(e,'tool.input',e.tool).blocked){blocked=true;notify();if(turnId)await $.turn.abort({turnId});return deny();}
    const result=await next(e);
    if(blocked||inspect(result,'tool.result',e.tool).blocked){blocked=true;notify();if(turnId)await $.turn.abort({turnId});return deny();}
    return result;
  }).catch(()=>{blocked=true;notify();lastRule='tool.hook.failed';lastEvent='tool.call';return deny();});
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
  }).catch(()=>{blocked=true;notify();lastRule=ready?'prompt.hook.failed':'initialization.failed';lastEvent='prompt.submit';return {drop:'SAFEGUARD_BLOCKED ['+lastRule+']; run /agent-safeguard-status'};});
  on('prompt.section',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;notify();return {text:null};}return r;}).catch(()=>{blocked=true;notify();lastRule=ready?'context.hook.failed':'initialization.failed';lastEvent='prompt.section';return {text:null};});
  on('prompt.context',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;notify();return {blocks:[]};}return r;}).catch(()=>{blocked=true;notify();lastRule=ready?'context.hook.failed':'initialization.failed';lastEvent='prompt.context';return {blocks:[]};});
  on('prompt.attachment',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;notify();return {text:null};}return r;}).catch(()=>{blocked=true;notify();lastRule=ready?'context.hook.failed':'initialization.failed';lastEvent='prompt.attachment';return {text:null};});
  on('agent.spawn',async ($,e,next)=>blocked||!ready?deny():next(e)).catch(()=>{blocked=true;notify();return deny();});
  on('session.compact',async ($,e,next)=>blocked||!ready?{skip:'SAFEGUARD_BLOCKED'}:next(e)).catch(()=>{blocked=true;notify();return {skip:'SAFEGUARD_BLOCKED'};});
  on('session.end',async ($,e,next)=>{if(blocked)finalDecision={rule:lastRule,event:lastEvent};blocked=true;notify();ready=false;lastRule='session.ended';lastEvent='session.end';lifecycle.ended=true;lifecycle.finish?.();return next(e);});
}
