import {compile,defaults,createSessionState} from '../dist/core.js';
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
        if(state.schema===3){
          while(lifecycle.events.length){const event=lifecycle.events[0];const archived={...row,session:event.recordId,interception:event,lastRule:event.ruleId,lastEvent:event.event};await $.fs.write(c.statusDir+'/interceptions/'+event.recordId+'.json',JSON.stringify(archived));lifecycle.events.shift();}
        }else if(state.interception&&!eventWritten){await $.fs.write(c.statusDir+'/interceptions/'+id+'.json',JSON.stringify(row));eventWritten=true;}
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
  let engine={version:defaults.ruleSetVersion,geoip:null},ready=false,blocked=false,lastRule=null,lastReason=null,initializing=null,lastEvent=null;const observed=new Set();
  const recovery=createSessionState();const modern=()=>engine.recovery==='next-safe-user-prompt';const locked=()=>modern()?recovery.blocked:blocked;
  const lifecycle={events:[],ended:false,timer:null,finish:null,identity:{agent:'Claude Code',hostSessionId:null,title:null,project:null,model:null,agentType:null}};let reporting=false,finalDecision=null,interception=null;const actors=new Map();
  const report=()=>({...(modern()?{schema:3,recovery:recovery.snapshot()}:{}),identity:lifecycle.identity,interception,pluginVersion:'0.2.2',ready,blocked:locked(),ended:lifecycle.ended,lastEvent:finalDecision?.event||lastEvent,ruleVersion:engine.version,lastRule:(finalDecision?.rule||lastRule)&&(['network.address','identity.device','identity.environment','security.credentials','inspection.failed','initialization.failed','prompt.hook.failed','context.hook.failed','session.ended','tool.hook.failed'].includes(finalDecision?.rule||lastRule)?(finalDecision?.rule||lastRule):'custom.rule')});
  function capture(rule,event,tool,agentId){
    if(interception&&!modern())return;
    interception={...(modern()?{recordId:crypto.randomUUID()}:{}),at:Date.now(),ruleId:!modern()?label(rule,80):['network.address','identity.device','identity.environment','security.credentials','inspection.failed','initialization.failed','tool.hook.failed','prompt.hook.failed','context.hook.failed'].includes(rule)?rule:'custom.rule',event,tool:label(tool,80),agentId:label(agentId,80),agentType:actors.get(agentId)||null,identity:{...lifecycle.identity}};
    if(modern()){if(lifecycle.events.length<32)lifecycle.events.push(interception);}
  }
  function inspect(value,source,tool,agentId){const r=engine.scan(value,source,tool);if(r.blocked){lastRule=r.rule;lastReason=r.reason||null;lastEvent=source;capture(r.rule,source,tool,agentId);}for(const id of r.observed||[])observed.add(id);return r;}
  function fail(rule,event){blocked=true;recovery.pauseCurrent(rule,true);lastRule=rule;lastReason=null;lastEvent=event;capture(rule,event);notify();}
  // Existing host events supply identity; no transcript scan or title generation.
  on('classic.SessionStart',($,e,next)=>{Object.assign(lifecycle.identity,{hostSessionId:label(e.session_id,80),project:label(e.cwd,512),title:label(e.session_title),agentType:label(e.agent_type,80),model:label(e.model,80)});notify();return next(e);});
  on('classic.UserPromptSubmit',($,e,next)=>{if(e.session_title)lifecycle.identity.title=label(e.session_title);notify();return next(e);});
  on('classic.CwdChanged',($,e,next)=>{lifecycle.identity.project=label(e.new_cwd,512);notify();return next(e);});
  on('classic.SubagentStart',($,e,next)=>{recovery.actorStart(e.agent_id);if(actors.size<64)actors.set(e.agent_id,label(e.agent_type,80));return next(e);});
  const notify=()=>lifecycle.publish?.(interception!==null);
  const deny=(phase)=>{
    if(!modern()||!phase)return {deny:'SAFEGUARD_BLOCKED'};
    const fault=lastRule==='inspection.failed';
    const reason=fault&&['inspection.timeout','inspection.text-limit','inspection.node-limit','inspection.depth-limit','inspection.invalid-structure','inspection.unsupported','inspection.exception'].includes(lastReason)?lastReason:fault?'inspection.failed':'rule.match';
    const action=reason==='inspection.timeout'?'Send a new safe message to run a local health check and continue. If that check fails, run /agent-safeguard-check.':fault?'Run /agent-safeguard-check, then submit a new safe message.':'After the current turn ends, submit a new safe message to continue.';
    return {deny:`SAFEGUARD_BLOCKED [${reason}]: ${phase==='input'?'Tool not executed.':'Tool ran; its result was withheld.'} ${action} Held operations and results are not replayed.`};
  };
  on('classic.SubagentStop',($,e,next)=>{recovery.actorStop(e.agent_id);return next(e);});
  on('session.start',async ($,e,next)=>{
    if(!reporting){reporting=true;lifecycle.identity.project=label(e.cwd,512);void startReports($,report,lifecycle);}
    await $.command.register({name:'agent-safeguard-status',description:'Show local safeguard status'});
    await $.command.register({name:'agent-safeguard-check',description:'Check safeguard health locally; never release held results'});
    engine = await (initializing ??= loadEngine($));
    ready = true;notify();
    return next(e);
  }).catch(()=>{ready=false;fail('initialization.failed','session.start');return {};});
  // Reason codes contain no values. Keep them in the on-demand status only:
  // existing desktop schema-2 readers reject unknown snapshot properties.
  on('command.run',{command:'agent-safeguard-status'},()=>({text:JSON.stringify({pluginVersion:'0.2.2',ready,blocked:locked(),recovery:modern()?recovery.snapshot():{state:blocked?'session-locked':'active'},...(modern()?{promptAdmission:recovery.admission()}:{}),lastEvent,ruleVersion:engine.version,geoip:engine.geoip,lastRule,lastReason,observedRules:[...observed],coverage:'experimental-tool-and-context-guard'})}));
  on('command.run',{command:'agent-safeguard-check'},async($,e)=>{
    if(!['composer','bridge','sdk'].includes(e.origin?.kind))return {text:'SAFEGUARD_CHECK_USER_REQUIRED'};
    try{const candidate=await loadEngine($);const clean=candidate.scan('SAFEGUARD_HEALTH_PROBE','tool.result','Bash');if(clean.blocked)return {text:'SAFEGUARD_CHECK_FAILED'};
      if(!recovery.healthRestored())return {text:'SAFEGUARD_RECOVERY_WAIT: wait for active work to end; context faults require fixing the context and restarting the instance'};
      engine=candidate;ready=true;initializing=Promise.resolve(candidate);notify();return {text:'SAFEGUARD_HEALTH_OK: submit a new safe message; held results remain withheld'};
    }catch{return {text:'SAFEGUARD_CHECK_FAILED'};}
  });
  on('turn.start',async ($,e,next)=>{recovery.start(e);return next(e);});
  on('turn.complete',($,e,next)=>{recovery.complete(e);notify();return next(e);});
  on('tool.call',async ($,e,next)=>{
    if(!ready||locked())return deny();
    const owner=modern()?recovery.begin(e):null;if(modern()&&!owner)return deny();
    try{
      if(inspect(e,'tool.input',e.tool,e.agentId).blocked){blocked=true;recovery.pause(owner,lastReason||lastRule,lastRule==='inspection.failed');notify();return deny('input');}
      const result=await next(e);
      if(locked()||(modern()&&!recovery.valid(owner)))return deny();
      const decision=engine.inspectAndTransform(result,'tool.result',e.tool);
      for(const id of decision.observed||[])observed.add(id);
      if(decision.kind==='pass')return result;
      if(decision.kind==='redacted'){
        // Do not retain ref: it points at the host's original, unsanitized messages.
        // Only verified synchronous Bash output shapes are enabled in this release.
        const r=result.result;
        const allowed=new Set(['stdout','stderr','interrupted','isImage','dangerouslyDisableSandbox','returnCodeInterpretation','noOutputExpected','memoryLimitNote','triggeredNote','staleReadFileStateHint','ghRateLimitHint']);
        const external=r&&typeof r==='object'&&Object.keys(r).some(k=>r[k]!=null&&!allowed.has(k));
        if(e.tool==='Bash'&&!external&&!r?.isImage&&(result.isError&&typeof r==='string'||r&&typeof r==='object'&&typeof r.stdout==='string'&&typeof r.stderr==='string')){
          if(modern()&&!recovery.valid(owner))return deny();
          recovery.stats.redactedResults++;recovery.stats.replacements+=decision.count;notify();
          // This host validates replacement Bash results as success records even
          // when isError is supplied. Its supported deny branch preserves an
          // error tool_result without fabricating a successful execution.
          if(result.isError)return {deny:decision.notice+'\n'+String(decision.value.text??decision.value.result)};
          return {result:decision.value.result,context:[...(decision.value.context||[]),decision.notice]};
        }
        decision.rule='network.address';decision.reason='redaction.unsupported-result';
      }
      lastRule=decision.rule;lastReason=decision.reason||null;lastEvent='tool.result';capture(lastRule,lastEvent,e.tool,e.agentId);
      // Return the refusal before stopping future model steps; do not abort
      // this dispatch and lose the reason to the host's cancellation placeholder.
      blocked=true;recovery.pause(owner,lastReason||lastRule,lastRule==='inspection.failed');notify();return deny('result');
    }catch{fail('tool.hook.failed','tool.call');return deny();}
    finally{recovery.finish(owner);notify();}
  }).catch(()=>{fail('tool.hook.failed','tool.call');return deny();});
  on('turn.step',async function* ($,e,next){
    if(!ready||locked()||(modern()&&!recovery.step(e))){yield {kind:'stop',stopReason:'end_turn',usage:null};return {turnId:e.turnId,index:e.index,answer:'',toolUses:[],stopReason:'end_turn',usage:null};}
    return yield* next(e);
  });
  on('prompt.submit',async ($,e,next)=>{
    let admission;
    engine = await (initializing ??= loadEngine($));
    ready = true;notify();
    if(!modern()&&blocked||inspect([e.text,...(e.context||[])],'user.prompt').blocked){
      if(!modern())blocked=true;else if(lastRule==='inspection.failed')recovery.pauseCurrent(lastRule,true);notify();
      return {drop:'SAFEGUARD_BLOCKED ['+(lastRule||'session.locked')+']; edit the message or run /agent-safeguard-status'};
    }
    if(modern()){
      // Only a drained timeout can retry. This uses the existing rule snapshot,
      // never releases the held call, and follows a successful scan of this prompt.
      if(recovery.canRecheckTimeout(e)){
        const health=engine.scan('SAFEGUARD_HEALTH_PROBE','tool.result','Bash');
        if(!health.blocked)recovery.healthRestored();
      }
      const reason=recovery.preparePrompt(e);if(reason)return {drop:(reason==='recovery.busy'?'SAFEGUARD_WAIT':'SAFEGUARD_PAUSED')+' ['+reason+']; '+(reason==='recovery.busy'?'the previous message submission has not finished; retry after it completes':reason==='recovery.health-required'?'run /agent-safeguard-check; if it reports a context fault, fix that context and restart the instance':'submit a safe user message after the previous turn ends')};
      admission=recovery.commitPrompt(e);if(!admission)return {drop:'SAFEGUARD_RECOVERY_WAIT'};
      blocked=false;lastRule=null;lastReason=null;lastEvent=null;notify();
    }
    try{return await next(e);}
    finally{if(admission){recovery.finishPrompt(admission);notify();}}
  }).catch(()=>{fail(ready?'prompt.hook.failed':'initialization.failed','prompt.submit');return {drop:'SAFEGUARD_BLOCKED ['+lastRule+']; run /agent-safeguard-status'};});
  on('prompt.section',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;recovery.pauseCurrent('context.blocked',true);notify();return {text:null};}return r;}).catch(()=>{fail(ready?'context.hook.failed':'initialization.failed','prompt.section');return {text:null};});
  on('prompt.context',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;recovery.pauseCurrent('context.blocked',true);notify();return {blocks:[]};}return r;}).catch(()=>{fail(ready?'context.hook.failed':'initialization.failed','prompt.context');return {blocks:[]};});
  on('prompt.attachment',async ($,e,next)=>{engine=await(initializing??=loadEngine($));ready=true;notify();const r=await next(e);if(engine.hasSource('prompt.context')&&inspect(r,'prompt.context').blocked){blocked=true;recovery.pauseCurrent('context.blocked',true);notify();return {text:null};}return r;}).catch(()=>{fail(ready?'context.hook.failed':'initialization.failed','prompt.attachment');return {text:null};});
  on('agent.spawn',async ($,e,next)=>{
    if(locked()||!ready)return deny();
    const owner=modern()?recovery.begin({agentId:e.parentAgentId}):null;if(modern()&&!owner)return deny();
    try{const result=await next(e);return locked()||modern()&&!recovery.valid(owner)?deny():result;}
    finally{recovery.finish(owner);notify();}
  }).catch(()=>{fail('tool.hook.failed','agent.spawn');return deny();});
  on('session.compact',async ($,e,next)=>locked()||!ready?{skip:'SAFEGUARD_BLOCKED'}:next(e)).catch(()=>{fail('context.hook.failed','session.compact');return {skip:'SAFEGUARD_BLOCKED'};});
  on('session.end',async ($,e,next)=>{if(locked())finalDecision={rule:lastRule,event:lastEvent};blocked=true;recovery.end();notify();ready=false;lastRule='session.ended';lastReason=null;lastEvent='session.end';lifecycle.ended=true;lifecycle.finish?.();return next(e);});
}
