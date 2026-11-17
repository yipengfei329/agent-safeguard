import ipaddr from 'ipaddr.js';
import {ipMatches} from './ip-matches.js';
import {createIPLabels,transformIPs,REDACTION_NOTICE} from './redaction.js';
export {createSessionState} from './session-state.js';
export {safeRule,safeReason,safeLocation,diagnosticCause,nextAction,actionText,refusal} from './diagnostics.js';
export {migrateRules} from './migration.js';
import {bundledGeoIP} from './geoip.js';
import {credentialReason} from './credentials.js';
import {createAssignmentDetector} from './identity-values.js';
import {simulatorIdentifier,maskSimulatorIdentifiers} from './simulator.js';
import validate from '../dist/validate.js';
import defaults from '../config/rules.example.json' with {type:'json'};
export {defaults};
const encoder=new TextEncoder();
const failure=(reason='inspection.limit-or-error')=>({blocked:true,rule:'inspection.failed',reason});
function addresses(text){
  return Array.from(ipMatches(text),m=>m.ip);
}
function matchesRanges(ip,ranges,budget){
  const mapped=ip.kind()==='ipv6'&&ip.isIPv4MappedAddress()?ip.toIPv4Address():null;
  return ranges.some(([net,len])=>{budget();return (ip.kind()===net.kind()&&ip.match(net,len))||(mapped&&net.kind()==='ipv4'&&mapped.match(net,len));});
}
const identityDetectors={
  'device-identifiers':createAssignmentDetector('(?:serial(?:number| number)?|udid|hardware[ _]*uuid|device[_ -]?id)',6),
  'personal-environment':createAssignmentDetector('(?:hostname|computername|localhostname)',1,'environment')
};
function identity(text,key,name,budget,syntax){
  if(name==='device-identifiers'&&/(?<![\w:-])[a-f0-9]{2}([:-])(?:[a-f0-9]{2}\1){4}[a-f0-9]{2}(?![\w:-])/i.test(text))return 'mac-format';
  return identityDetectors[name](text,key,budget,syntax);
}

export function compile(config=defaults,options={}){
  config=JSON.parse(JSON.stringify(config));
  if(encoder.encode(JSON.stringify(config)).length>1048576 || !validate(config)) throw Error('INVALID_RULE_CONFIG');
  const ids=new Set();let count=0;
  if(config.rules.length>config.limits.maxRules)throw Error('RULE_LIMIT');
  const rules=config.rules.filter(r=>{
    if(ids.has(r.id))throw Error('DUPLICATE_RULE');ids.add(r.id);
    if(r.tools&&r.sources.some(s=>!s.startsWith('tool.')))throw Error('INVALID_TOOL_SCOPE');
    return true;
  }).map(r=>{
    const d=r.detector;
    if(r.action==='redact'&&(config.schemaVersion!==2||d.kind!=='ip'||r.sources.length!==1||r.sources[0]!=='tool.result'))throw Error('INVALID_REDACTION_SCOPE');
    count+=(d.values||d.cidrs||d.suffixes||[]).length+(d.excludeCidrs||[]).length;
    let ranges=[];
    if(d.kind==='ip'&&d.mode==='cidr')ranges=d.cidrs.map(c=>ipaddr.parseCIDR(c));
    if(d.kind==='domain'&&d.suffixes.some(s=>! /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(s)))throw Error('INVALID_DOMAIN');
    const exclusions=d.kind==='ip'?(d.excludeCidrs||[]).map(c=>ipaddr.parseCIDR(c)):[];
    return {...r,detector:{...d},ranges,exclusions};
  }).filter(r=>r.enabled);
  if(count>config.limits.maxMatchValues)throw Error('VALUE_LIMIT');
  const geo=rules.some(r=>r.detector.kind==='ip'&&r.detector.mode==='country')?(options.geoip??bundledGeoIP()):null;
  const limits={...config.limits},version=config.ruleSetVersion;
  const labels=createIPLabels(),redactions=rules.filter(r=>r.action==='redact');
  const selected=(r,source,tool)=>r.sources.includes(source)&&(!r.tools||r.tools.includes(tool));
  function scan(value,source='tool.result',tool='',deadline=Date.now()+100,skipRedact=false){
    try {
      const observed=new Set();let operations=0;const budget=()=>{if((++operations&31)===0&&Date.now()>deadline)throw Error('inspection.timeout');};
      let bytes=0,nodes=0,textCount=0;const seen=new Set();const active=rules.filter(r=>selected(r,source,tool)&&(!skipRedact||r.action!=='redact'));
      function text(s,decode=0,key="",simulator=false){
        const textIndex=++textCount;
        bytes+=encoder.encode(s).length;if(bytes>limits.maxTextBytes)throw Error('inspection.text-limit');
        // Credential evidence and device scope come from decoded JSON values.
        // Other rule kinds retain their existing raw-text semantics.
        let decoded,hasDecoded=false;
        if(decode<limits.maxNestedJsonDecodes&&/^\s*[\[{"]/.test(s)) {try{decoded=JSON.parse(s);hasDecoded=true;}catch{}}
        const normalized=s.replace(/\\u([0-9a-f]{4})/gi,(_,v)=>String.fromCharCode(parseInt(v,16))).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'');
        let ips,deviceText;const syntax={recordLocation:options.diagnostics===true};
        for(const r of active){
          budget();syntax.match=null;const d=r.detector;let hit=false,reason=null;
          if(d.kind==='ip') {ips??=addresses(normalized);hit=ips.some(ip=>!matchesRanges(ip,r.exclusions,budget)&&(d.mode==='any'||(d.mode==='country'?geo.lookup(ip)===1:matchesRanges(ip,r.ranges,budget))));}
          if(d.kind==='exact')hit=d.values.some(v=>{budget();return d.caseSensitive?normalized.includes(v):normalized.toLowerCase().includes(v.toLowerCase());});
          if(d.kind==='domain'){const lower=normalized.toLowerCase();hit=d.suffixes.some(v=>{v=v.toLowerCase();let at=-1;while((at=lower.indexOf(v,at+1))!==-1){const before=lower[at-1]||'',after=lower[at+v.length]||'';if(!/[a-z0-9_-]/.test(before)&&(!/[a-z0-9_.-]/.test(after)||(after==='.'&&!/[a-z0-9_.-]/.test(lower[at+v.length+1]||''))))return true;}return false;});}
          if(d.kind==='builtin'){
            if(d.name==='credentials'){if(!hasDecoded)reason=credentialReason(normalized,key,budget,syntax);hit=reason!==null;}
            else if(d.name==='device-identifiers'){
              if(!hasDecoded&&!simulator){deviceText??=maskSimulatorIdentifiers(normalized,budget);reason=identity(deviceText,key,d.name,budget,syntax);hit=reason!==null;}
            }else{reason=identity(normalized,key,d.name,budget,syntax);hit=reason!==null;}
          }
          if(hit&&r.action!=='observe'){
            let location;
            if(syntax.match){let line=1,at=-1;while((at=normalized.indexOf('\n',at+1))>=0&&at<syntax.match.offset){budget();line++;}location={textIndex,line,field:syntax.match.field};}
            return {blocked:true,rule:r.id,...(reason?{reason}:{}),...(location?{location}:{})};
          }if(hit)observed.add(r.id);
        }
        if(hasDecoded)return visit(decoded,1,decode+1,key);
        return null;
      }
      function visit(v,depth=0,decode=0,inheritedKey=''){
        budget();
        if(++nodes>limits.maxNodes)throw Error('inspection.node-limit');if(depth>limits.maxDepth)throw Error('inspection.depth-limit');
        if(typeof v==='string')return text(v,decode,inheritedKey);
        if(typeof v==='number'&&inheritedKey)return text(String(v),decode,inheritedKey);
        if(v===null||v===undefined||typeof v==='boolean'||typeof v==='number')return null;
        if(typeof v!=='object'||seen.has(v))throw Error('inspection.invalid-structure');seen.add(v);
        const mime=v.mimeType||v.media_type;
        const unsupported=['image','audio','video','document','resource_link','base64'].includes(v.type)||
          typeof mime==='string'&&!mime.startsWith('text/')&&mime!=='application/json'||v.base64!==undefined;
        if(unsupported&&config.policy.onUnsupportedContent==='block')throw Error('inspection.unsupported');
        for(const [k,x] of Object.entries(v)){
          // Opaque bytes are not text. Keep inspecting captions, URLs, metadata
          // and adjacent text blocks; an image must not exempt its whole result.
          if(unsupported&&['data','base64','bytes','buffer'].includes(k))continue;
          const a=text(k,decode);if(a)return a;
          if(typeof x==='string'){if(++nodes>limits.maxNodes)throw Error('inspection.node-limit');const a=text(x,decode,Array.isArray(v)?inheritedKey:k,simulatorIdentifier(v,k,x));if(a)return a;}else{const b=visit(x,depth+1,decode,Array.isArray(v)?inheritedKey:k);if(b)return b;}
        }
        seen.delete(v);return null;
      }
      const result=visit(value);if(Date.now()>deadline)return failure('inspection.timeout');return result||{blocked:false,observed:[...observed]};
    }catch(error){return failure(['inspection.timeout','inspection.text-limit','inspection.node-limit','inspection.depth-limit','inspection.invalid-structure','inspection.unsupported'].includes(error?.message)?error.message:'inspection.exception');}
  }
  return {version,geoip:geo?.metadata??null,recovery:config.schemaVersion===2?config.policy.recovery:'session-lock',hasSource(source){return rules.some(r=>r.sources.includes(source));},scan,
    inspectAndTransform(value,source='tool.result',tool=''){
      const deadline=Date.now()+100;
      if(!redactions.some(r=>selected(r,source,tool))){const r=scan(value,source,tool,deadline);return r.blocked?{kind:'withhold',...r}:{kind:'pass',observed:r.observed};}
      // Every blocking rule sees the original, before any value is replaced.
      const original=scan(value,source,tool,deadline,true);
      if(original.blocked)return {kind:'withhold',...original};
      const probe=scan(value,source,tool,deadline);
      if(!probe.blocked)return {kind:'pass',observed:original.observed};
      if(probe.rule==='inspection.failed')return {kind:'withhold',...probe};
      try{
        const active=redactions.filter(r=>selected(r,source,tool));
        const matches=ip=>active.some(r=>!matchesRanges(ip,r.exclusions,()=>{})&&(r.detector.mode==='any'||(r.detector.mode==='country'?geo.lookup(ip)===1:matchesRanges(ip,r.ranges,()=>{}))));
        const changed=transformIPs(value,{matches,limits,deadline,labels});
        if(!changed.count)return {kind:'withhold',blocked:true,rule:probe.rule,reason:'redaction.unsupported'};
        const checked=scan([changed.value,REDACTION_NOTICE],source,tool,deadline);
        if(checked.blocked)return {kind:'withhold',...checked,reason:checked.reason||'redaction.residual'};
        return {kind:'redacted',value:changed.value,notice:REDACTION_NOTICE,count:changed.count,observed:original.observed};
      }catch(error){
        const fallback=['redaction.ambiguous-json','redaction.sensitive-key','redaction.unsupported'];
        const faults=['redaction.capacity','redaction.match-limit','inspection.timeout','inspection.text-limit','inspection.structure-limit'];
        const reason=[...fallback,...faults].includes(error?.message)?error.message:'redaction.failed';
        return {kind:'withhold',blocked:true,rule:fallback.includes(reason)?probe.rule:'inspection.failed',reason};
      }
    }
  };
}
