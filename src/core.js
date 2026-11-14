import ipaddr from 'ipaddr.js';
import validate from '../dist/validate.js';
import defaults from '../config/rules.example.json' with {type:'json'};
export {defaults};
const encoder=new TextEncoder();
const failure=()=>({blocked:true,rule:'inspection.failed'});
function addresses(text){
  const result=[];
  for(const m of text.matchAll(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:.]*(?:%[\w.-]+)?/g)) {
    try { if(ipaddr.isValid(m[0])) result.push(ipaddr.parse(m[0])); } catch {}
  }
  return result;
}
function matchesRanges(ip,ranges,budget){
  const mapped=ip.kind()==='ipv6'&&ip.isIPv4MappedAddress()?ip.toIPv4Address():null;
  return ranges.some(([net,len])=>{budget();return (ip.kind()===net.kind()&&ip.match(net,len))||(mapped&&net.kind()==='ipv4'&&mapped.match(net,len));});
}
const detectors={
  credentials: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:password|passwd|access_token|api[_-]?key|secret|authorization)\s*["']?\s*[:=]\s*["']?[^\s"',;}]{4,}|\b[a-z][a-z0-9+.-]*:\/\/[^\s/:]+:[^\s/@]+@/i,
  'device-identifiers': /\b(?:serial(?:number| number)?|udid|hardware\s*uuid|device[_ -]?id)\s*["']?\s*[:=]\s*["']?[a-z0-9][a-z0-9-]{5,}|(?<![\w:])(?:[a-f0-9]{2}:){5}[a-f0-9]{2}(?![\w:])/i,
  'personal-environment': /\b(?:hostname|computername|localhostname)\s*["']?\s*[:=]\s*["']?[\w.-]+/i
};
export function compile(config=defaults){
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
    count+=(d.values||d.cidrs||d.suffixes||[]).length+(d.excludeCidrs||[]).length;
    let ranges=[];
    if(d.kind==='ip'&&d.mode==='cidr')ranges=d.cidrs.map(c=>ipaddr.parseCIDR(c));
    if(d.kind==='domain'&&d.suffixes.some(s=>! /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(s)))throw Error('INVALID_DOMAIN');
    const exclusions=d.kind==='ip'?(d.excludeCidrs||[]).map(c=>ipaddr.parseCIDR(c)):[];
    return {...r,detector:{...d},ranges,exclusions};
  }).filter(r=>r.enabled);
  if(count>config.limits.maxMatchValues)throw Error('VALUE_LIMIT');
  const limits={...config.limits},version=config.ruleSetVersion;
  return {version,hasSource(source){return rules.some(r=>r.sources.includes(source));},scan(value,source='tool.result',tool=''){
    try {
      const observed=new Set();const deadline=Date.now()+100;let operations=0;const budget=()=>{if((++operations&31)===0&&Date.now()>deadline)throw Error();};
      let bytes=0,nodes=0;const seen=new Set();const active=rules.filter(r=>r.sources.includes(source)&&(!r.tools||r.tools.includes(tool)));
      function text(s,decode=0,key=""){
        bytes+=encoder.encode(s).length;if(bytes>limits.maxTextBytes)throw Error();
        const normalized=s.replace(/\\u([0-9a-f]{4})/gi,(_,v)=>String.fromCharCode(parseInt(v,16))).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'');
        let ips;
        for(const r of active){
          budget();const d=r.detector;let hit=false;
          if(d.kind==='ip') {ips??=addresses(normalized);hit=ips.some(ip=>!matchesRanges(ip,r.exclusions,budget)&&(d.mode==='any'||matchesRanges(ip,r.ranges,budget)));}
          if(d.kind==='exact')hit=d.values.some(v=>{budget();return d.caseSensitive?normalized.includes(v):normalized.toLowerCase().includes(v.toLowerCase());});
          if(d.kind==='domain'){const lower=normalized.toLowerCase();hit=d.suffixes.some(v=>{v=v.toLowerCase();let at=-1;while((at=lower.indexOf(v,at+1))!==-1){const before=lower[at-1]||'',after=lower[at+v.length]||'';if(!/[a-z0-9_-]/.test(before)&&!/[a-z0-9_.-]/.test(after))return true;}return false;});}
          if(d.kind==='builtin'){const candidate=key?key+': '+normalized:normalized;hit=detectors[d.name].test(candidate);}
          if(hit&&r.action==='block')return {blocked:true,rule:r.id};if(hit)observed.add(r.id);
        }
        if(decode<limits.maxNestedJsonDecodes&&/^\s*[\[{"]/.test(s)) {let obj;try{obj=JSON.parse(s);}catch{}if(obj!==undefined)return visit(obj,1,decode+1);}
        return null;
      }
      function visit(v,depth=0,decode=0){
        budget();
        if(++nodes>limits.maxNodes||depth>limits.maxDepth)throw Error();
        if(typeof v==='string')return text(v,decode);
        if(v===null||v===undefined||typeof v==='boolean'||typeof v==='number')return null;
        if(typeof v!=='object'||seen.has(v))throw Error();seen.add(v);
        if(['image','audio','document','resource_link'].includes(v.type)||v.mimeType&& !v.mimeType.startsWith('text/')&&v.mimeType!=='application/json'||v.base64!==undefined)throw Error();
        for(const [k,x] of Object.entries(v)){
          const a=text(k,decode);if(a)return a;
          if(typeof x==='string'){if(++nodes>limits.maxNodes)throw Error();const a=text(x,decode,k);if(a)return a;}else{const b=visit(x,depth+1,decode);if(b)return b;}
        }
        seen.delete(v);return null;
      }
      const result=visit(value);if(Date.now()>deadline)return failure();return result||{blocked:false,observed:[...observed]};
    }catch{return failure();}
  }};
}
