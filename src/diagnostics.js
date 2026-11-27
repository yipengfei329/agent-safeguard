// Only fixed vocabulary may cross the diagnostic boundary. Never interpolate
// payloads, exception messages, custom rule IDs or external tool names.
const rules=new Set(['network.address','identity.device','identity.environment','security.credentials','inspection.failed','initialization.failed','tool.hook.failed','prompt.hook.failed','context.hook.failed','session.ended']);
const reasons=new Set(['inspection.failed','initialization.failed','tool.hook.failed','prompt.hook.failed','context.hook.failed','private-key','token-format','url-password','mac-format','literal-value','block-scalar','encoded-literal','authorization-value','unquoted-value','structured-value','inspection.timeout','inspection.text-limit','inspection.node-limit','inspection.depth-limit','inspection.invalid-structure','inspection.unsupported','inspection.exception','inspection.limit-or-error','redaction.unsupported','redaction.residual','redaction.unsupported-result','redaction.placeholder-input']);
const events=new Set(['tool.input','tool.result','tool.call','user.prompt','session.start','prompt.submit','prompt.section','prompt.context','prompt.attachment','agent.spawn','session.compact']);
export const safeRule=value=>value==null?null:value==='network.address.output'?'network.address':rules.has(value)?value:'custom.rule';
export const safeReason=value=>reasons.has(value)?value:'rule.match';
export function safeLocation(value){return value&&Number.isSafeInteger(value.textIndex)&&value.textIndex>0&&Number.isSafeInteger(value.line)&&value.line>0&&['token','password','device','hostname','computer'].includes(value.field)?{textIndex:value.textIndex,line:value.line,field:value.field}:null;}
export function diagnosticCause(rule,reason,event,tool,location){return {...(safeLocation(location)?{location:safeLocation(location)}:{}),rule:safeRule(rule),reason:safeReason(reason||(rules.has(rule)&&rule.endsWith('.failed')?rule:null)),event:events.has(event)?event:'tool.call',tool:['Bash','Write','Edit','Read','Grep','Glob'].includes(tool)?tool:null};}
export function nextAction({ready,blocked,modern,ended,barrier={},recovery={},admission={}}){
 if(ended)return 'restart';
 if(!ready)return blocked?'health-check':'initializing';
 if(blocked&&!modern)return 'restart';
 if(barrier.contextBlocked)return 'fix-context-restart';
 if(admission.submitting)return 'wait-submission';
 if(blocked){
  if(recovery.inFlight||admission.activeTurns||admission.activeAgents)return 'wait-work';
  if(barrier.hard)return barrier.timeout?'safe-message-probe':'health-check';
  return recovery.canResume?'safe-message':'wait-work';
 }
 return 'continue';
}
export const actionText=action=>({
 'restart':'Restart the plugin instance or start a new session.',
 'initializing':'Wait for plugin initialization; check /agent-safeguard-status.',
 'fix-context-restart':'Fix the blocked context and restart the instance; a new message cannot clear this barrier.',
 'wait-submission':'Wait for the previous message submission to finish, then retry.',
 'wait-work':'Wait for the current turn, tools and agents to end, then submit a new safe message.',
 'safe-message-probe':'Send a new safe message to run a local health check and continue. If that check fails, run /agent-safeguard-check.',
 'health-check':'Run /agent-safeguard-check, then submit a new safe message.',
 'safe-message':'Submit a new safe message to continue.',
 'continue':'The session is active; continue with a safe message.'
}[action]||'Check /agent-safeguard-status.');
export function refusal({effect,cause,action,related=false,stale=false,afterAction=null}){
 const outcome={input:'Tool not executed.',result:'Tool ran; its result was withheld.',unknown:'Execution status is unknown; no result was released.',spawn:'Agent not started.','spawn-result':'Agent start was attempted; its response was withheld.'}[effect]||'Operation withheld.';
 const code=stale?'recovery.stale-owner':related?'session.paused':cause?.reason||'session.unavailable';
 const origin=cause?`${related?' Earlier pause:':' Cause:'} ${cause.rule} / ${cause.reason} at ${cause.event}${cause.tool?' ('+cause.tool+')':''}.`:'';
 const hint=cause?.rule==='identity.device'?' Device identifier detected without an applicable exemption; truncated records cannot establish simulator platform.':cause?.reason==='url-password'?' URL password detected; example domains do not exempt credentials.':'';
 const extraAction=afterAction&&afterAction!==action&&!(action==='wait-work'&&afterAction==='safe-message');
 return `SAFEGUARD_BLOCKED [${code}]: ${outcome}${origin}${hint}${cause?.location?' Location: scanned text '+cause.location.textIndex+', line '+cause.location.line+', '+cause.location.field+' field (not a source-file line).':''} ${actionText(action)}${extraAction?' Then: '+actionText(afterAction):''} Held operations and results are not replayed.`;
}
