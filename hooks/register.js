import {compile,defaults} from '../dist/core.js';
async function loadEngine($) {
  const path = $.plugin.root + '/local/rules.json';
  if (!(await $.fs.exists(path))) return compile(defaults);
  const raw = await $.fs.read(path, {length:1048577});
  if (new TextEncoder().encode(raw).length > 1048576) throw Error('CONFIG_LIMIT');
  return compile(JSON.parse(raw));
}
export function register(on){
  let engine=compile(defaults),ready=false,blocked=false,turnId=null,lastRule=null,initializing=null,lastEvent=null;const observed=new Set();
  function inspect(value,source,tool){const r=engine.scan(value,source,tool);if(r.blocked){lastRule=r.rule;lastEvent=source;}for(const id of r.observed||[])observed.add(id);return r;}
  const deny=()=>({deny:'SAFEGUARD_BLOCKED'});
  on('session.start',async ($,e,next)=>{
    await $.command.register({name:'agent-safeguard-status',description:'Show local safeguard status'});
    engine = await (initializing ??= loadEngine($));
    ready = true;
    return next(e);
  }).catch(()=>{blocked=true;ready=false;lastRule='initialization.failed';lastEvent='session.start';return {};});
  on('command.run',{command:'agent-safeguard-status'},()=>({text:JSON.stringify({pluginVersion:'0.1.5',ready,blocked,lastEvent,ruleVersion:engine.version,lastRule,observedRules:[...observed],coverage:'experimental-tool-and-context-guard'})}));
  on('turn.start',async ($,e,next)=>{if(!e.agentId)turnId=e.turnId;return next(e);});
  on('tool.call',async ($,e,next)=>{
    if(!ready||blocked)return deny();
    if(inspect(e,'tool.input',e.tool).blocked){blocked=true;if(turnId)await $.turn.abort({turnId});return deny();}
    const result=await next(e);
    if(blocked||inspect(result,'tool.result',e.tool).blocked){blocked=true;if(turnId)await $.turn.abort({turnId});return deny();}
    return result;
  }).catch(()=>{blocked=true;return deny();});
  on('turn.step',async function* ($,e,next){
    if(!ready||blocked){yield {kind:'stop',stopReason:'end_turn',usage:null};return {turnId:e.turnId,index:e.index,answer:'',toolUses:[],stopReason:'end_turn',usage:null};}
    return yield* next(e);
  });
  on('prompt.submit',async ($,e,next)=>{
    engine = await (initializing ??= loadEngine($));
    ready = true;
    if(blocked||inspect(e.text,'user.prompt').blocked){
      blocked=true;
      return {drop:'SAFEGUARD_BLOCKED ['+(lastRule||'session.locked')+']; run /agent-safeguard-status'};
    }
    return next(e);
  }).catch(()=>{blocked=true;lastRule=ready?'prompt.hook.failed':'initialization.failed';lastEvent='prompt.submit';return {drop:'SAFEGUARD_BLOCKED ['+lastRule+']; run /agent-safeguard-status'};});
  on('prompt.section',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;return {text:null};}return r;}).catch(()=>{blocked=true;lastRule=ready?'context.hook.failed':'initialization.failed';lastEvent='prompt.section';return {text:null};});
  on('prompt.context',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;return {blocks:[]};}return r;}).catch(()=>{blocked=true;lastRule=ready?'context.hook.failed':'initialization.failed';lastEvent='prompt.context';return {blocks:[]};});
  on('prompt.attachment',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;return {text:null};}return r;}).catch(()=>{blocked=true;lastRule=ready?'context.hook.failed':'initialization.failed';lastEvent='prompt.attachment';return {text:null};});
  on('agent.spawn',async ($,e,next)=>blocked||!ready?deny():next(e)).catch(()=>{blocked=true;return deny();});
  on('session.compact',async ($,e,next)=>blocked||!ready?{skip:'SAFEGUARD_BLOCKED'}:next(e)).catch(()=>{blocked=true;return {skip:'SAFEGUARD_BLOCKED'};});
  on('session.end',async ($,e,next)=>{blocked=true;ready=false;lastRule='session.ended';lastEvent='session.end';return next(e);});
}
