// Pure migration: callers validate both input and output and explicitly save.
export function migrateRules(config,{redactIds=[]}={}){
 const out=JSON.parse(JSON.stringify(config));out.schemaVersion=2;
 out.policy.recovery='next-safe-user-prompt';
 const requested=new Set(redactIds),ids=new Set(out.rules.map(r=>r.id));
 out.rules=out.rules.flatMap(r=>{
  if(!requested.has(r.id))return [r];requested.delete(r.id);
  if(r.action!=='block'||r.detector.kind!=='ip'||!r.sources.includes('tool.result'))throw Error('INVALID_MIGRATION_SELECTION');
  const sources=r.sources.filter(s=>s!=='tool.result');
  if(!sources.length)return [{...r,action:'redact'}];
  const outputId=r.id+'.output';if(outputId.length>80||ids.has(outputId))throw Error('MIGRATION_ID_CONFLICT');ids.add(outputId);
  return [{...r,sources},{...r,id:outputId,sources:['tool.result'],action:'redact'}];
 });
 if(requested.size)throw Error('MIGRATION_RULE_MISSING');
 out.ruleSetVersion='v2-'+out.ruleSetVersion.slice(0,77);return out;
}
