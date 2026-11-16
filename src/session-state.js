// Pure lifecycle state. Host provenance is pinned; plugin/peer/background input
// is never a recovery grant. SDK is an explicitly trusted host ingress, not a
// claim that every SDK caller is human. See the supported-ingress documentation.
export function createSessionState(){
 let serial=0,current=make(),ended=false,grant=false,accepting=false;
 const turns=new Map(),actors=new Map(),alive=new Set();
 const stats={pauses:0,resumes:0,redactedResults:0,replacements:0};
 function make(){return {epoch:++serial,paused:false,hard:false,contextBlocked:false,pending:0,turns:new Set(),reason:null};}
 const trusted=e=>!e.isMeta&&!e.command&&['composer','bridge','sdk'].includes(e.origin?.kind);
 const drained=()=>!current.pending&&!current.turns.size&&!alive.size&&!accepting&&!ended;
 const canResume=()=>current.paused&&!current.hard&&drained();
 return {
  stats,
  snapshot(){return {state:ended?'ended':current.hard?'faulted':current.paused?(current.pending||current.turns.size?'pausing':'paused'):'active',epoch:current.epoch,inFlight:current.pending,canResume:canResume(),...stats};},
  get blocked(){return ended||current.paused;},
  // A per-operation timeout may be rechecked at a new trusted input boundary.
  // Unknown failures, capacity faults and contaminated context stay manual.
  canRecheckTimeout(e){return trusted(e)&&current.paused&&current.hard&&current.reason==='inspection.timeout'&&!current.contextBlocked&&!grant&&drained();},
  preparePrompt(e){
   if(ended)return 'session.ended';
   if(accepting||grant)return 'recovery.busy';
   if(current.epoch>1&&!trusted(e))return 'recovery.user-required';
   if(current.paused){if(!trusted(e))return 'recovery.user-required';if(!canResume())return current.hard&&drained()?'recovery.health-required':'recovery.wait';}
   accepting=true;return null;
  },
  commitPrompt(e){
   accepting=false;
   if(current.paused){if(!trusted(e)||!canResume())return false;current=make();stats.resumes++;}
   if(trusted(e))grant=true;return true;
  },
  cancelPrompt(){accepting=false;grant=false;},
  start(e){
   if(turns.size>=4096){this.pause(current,'recovery.capacity',true);return;}
   if(e.agentId){const parent=actors.get(e.agentId);turns.set(e.turnId,parent||null);if(parent)parent.turns.add(e.turnId);return;}
   // Recovery does not authorize automatic root continuations. Without a
   // submitted prompt's grant their model steps remain stopped.
   if(current.epoch>1&&!grant){turns.set(e.turnId,null);return;}
   turns.set(e.turnId,current);current.turns.add(e.turnId);grant=false;
  },
  complete(e){const owner=turns.get(e.turnId);owner?.turns.delete(e.turnId);turns.delete(e.turnId);},
  actorStart(id){if(!actors.has(id)&&actors.size<4096){actors.set(id,current);alive.add(id);}else if(!actors.has(id))this.pauseCurrent('recovery.capacity',true);},
  actorStop(id){alive.delete(id);/* Keep ownership for late callbacks. */},
  begin(e){const owner=e.agentId?actors.get(e.agentId):current;if(!owner||owner!==current||owner.paused||ended)return null;owner.pending++;return owner;},
  finish(owner){if(owner)owner.pending--;},
  valid(owner){return !ended&&owner===current&&!owner.paused;},
  step(e){const owner=turns.get(e.turnId);return !ended&&owner===current&&!owner.paused;},
  pause(owner,reason,hard=false){if(!owner||owner!==current)return false;if(!owner.paused)stats.pauses++;owner.paused=true;owner.hard ||= hard;owner.contextBlocked ||= ['context.blocked','context.hook.failed'].includes(reason);owner.reason=reason;grant=false;return true;},
  pauseCurrent(reason,hard=false){return this.pause(current,reason,hard);},
  healthRestored(){if(current.pending||current.turns.size||alive.size||ended||current.contextBlocked)return false;current.hard=false;return true;},
  end(){ended=true;current.paused=true;},
 };
}
