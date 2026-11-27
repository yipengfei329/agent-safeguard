import {ipMatches,canonicalIP} from './ip-matches.js';
export const REDACTION_NOTICE='[Agent Safeguard] Sensitive IP addresses were replaced with instance-local labels. Labels are not real addresses; do not use them for connections or configuration.';
const enc=new TextEncoder();
// No disk, no stable hashes, no reverse-resolution API. Entries live only in this
// engine instance and are bounded. Raw values already exist in the input buffer.
export function createIPLabels(limit=4096){
 const labels=new Map();
 return {get(ip){const key=canonicalIP(ip);if(!labels.has(key)){if(labels.size>=limit)throw Error('redaction.capacity');labels.set(key,`[IP_${labels.size+1}]`);}return labels.get(key);},size:()=>labels.size};
}
// Preserve a source span for every normalized character, including escaped
// Unicode and ANSI inserted inside an address. Never apply normalized offsets
// directly to the original text.
function normalized(text){
 const chars=[],starts=[],ends=[];const re=/\\u([0-9a-f]{4})|\x1b\[[0-?]*[ -/]*[@-~]/gi;let at=0;
 for(const m of text.matchAll(re)){
  for(let i=at;i<m.index;i++){chars.push(text[i]);starts.push(i);ends.push(i+1);}
  if(m[1]){chars.push(String.fromCharCode(parseInt(m[1],16)));starts.push(m.index);ends.push(m.index+m[0].length);}
  at=m.index+m[0].length;
 }
 for(let i=at;i<text.length;i++){chars.push(text[i]);starts.push(i);ends.push(i+1);}
 return {text:chars.join(''),starts,ends};
}
const sourceLine=/(?:const|let|var|function|class|import|export|return|def|pub|fn|SELECT|INSERT|UPDATE|diff|@@|[+-]{3})\b/;
const sourceExpression=/=>|\b(?:curl|wget|ssh)\s|\$\(|[`;]/;
const sourceLike=new RegExp('^[ \\t]*(?:\\d{1,10}[:-][ \\t]*)?'+sourceLine.source+'|'+sourceExpression.source+'|[{}]','m');
const diagnosticWords=/\b(?:peer|local|remote|address|addr|endpoint|connect(?:ed|ion)?|listen(?:ing)?|dial|network|src|dst|server|client|from|to)\b/i;
const sourcePosition=/[ \t]*[^\s:=][^:=\r\n]*:\d{1,10}:/y;
const logValue=/(?:"(?:[^"\\\r\n]|\\[^\r\n])*"|[^\s"'=;{}`]+)/;
const logField='[ \\t]+[A-Za-z_][\\w.-]*='+logValue.source;
const logFields='(?:'+logField+')*';
const logHeader=/^(?:\d{1,10}[:-])?[ \t]*time=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)[ \t]+level=(?:DEBUG|INFO|WARN|ERROR)[ \t]+msg=/;
const logAddressPrefix=new RegExp(logHeader.source+logValue.source+logFields+'[ \\t]+(?:addr|address|local|remote|peer|endpoint)=(\\[?)$');
const bareAddressEnd=new RegExp('^(?::\\d{1,5})?'+logFields+'[ \\t]*\\r?$');
const bracketAddressEnd=new RegExp('^\\](?::\\d{1,5})?'+logFields+'[ \\t]*\\r?$');
const runtimeLogLine=/^[ \t]*(?:\d{4}[/-]\d\d[/-]\d\d[ T]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:?\d\d)?[ \t]+|(?:DEBUG|INFO|WARN(?:ING)?|ERROR):[\w.-]+:)/;

// Plain diagnostics retain their existing rule. Mixed output requires positive
// record evidence at every protected span, independent of adjacent test titles
// and source. A grep file position never supplies that evidence.
function redactableText(text,spans,structured,budget){
 const code=sourceLike.test(text);
 if(structured)return !code;
 const plainDiagnostic=!code&&diagnosticWords.test(text);
 let lineStart=0,lineEnd=-1,plainLine=false;
 for(const {start,end} of spans){
  budget();
  if(start>=lineEnd){
   lineStart=text.lastIndexOf('\n',start-1)+1;
   const nextLine=text.indexOf('\n',start);
   lineEnd=nextLine===-1?text.length:nextLine;
   sourcePosition.lastIndex=lineStart;
   const hasPos=sourcePosition.test(text);
   const line=text.slice(lineStart,lineEnd);
   const isRuntimeLog=line.length<=2048&&runtimeLogLine.test(line)&&!sourceLike.test(line)&&diagnosticWords.test(line);
   plainLine=isRuntimeLog||(!hasPos&&plainDiagnostic);
  }
  if(plainLine)continue;
  if(lineEnd-lineStart>2048)return false;
  const prefix=logAddressPrefix.exec(text.slice(lineStart,start));
  if(!prefix)return false;
  const addressEnd=prefix[1]?bracketAddressEnd:bareAddressEnd;
  if(!addressEnd.test(text.slice(end,lineEnd)))return false;
 }
 return true;
}
// JSON.parse alone silently discards duplicate keys. Refuse these before parse.
function duplicateKeys(s){
 const stack=[];let i=0;
 while(i<s.length){const c=s[i];if(c==='{'||c==='['){stack.push(c==='{'?new Set():null);i++;continue;}if(c==='}'||c===']'){stack.pop();i++;continue;}
  if(c==='"'){let end=i+1;for(;end<s.length;end++){if(s[end]==='\\'){end++;continue;}if(s[end]==='"')break;}
   let next=end+1;while(/\s/.test(s[next]||'x'))next++;
   if(s[next]===':'&&stack.at(-1) instanceof Set){const key=JSON.parse(s.slice(i,end+1));if(stack.at(-1).has(key))return true;stack.at(-1).add(key);}i=end+1;
  }else i++;
 }
 return false;
}
const malformedJson=/^\s*(?:\{|\[\s*(?:["{\[]|-?\d+(?:\.\d+)?\s*(?:,|\]|$)|(?:true|false|null)\b))/;
export function transformIPs(value,{matches,limits,deadline,labels}){
 let bytes=0,nodes=0,count=0;const seen=new Set();
 const budget=()=>{if(Date.now()>deadline)throw Error('inspection.timeout');};
 function text(s,depth,decode,key=false,structured=false){
  budget();bytes+=enc.encode(s).length;if(bytes>limits.maxTextBytes)throw Error('inspection.text-limit');
  if(decode<limits.maxNestedJsonDecodes&&/^\s*[\[{"]/.test(s)){
   let parsed,valid=false;try{parsed=JSON.parse(s);valid=true;}catch{}
   if(valid){if(duplicateKeys(s))throw Error('redaction.ambiguous-json');const before=count;const result=visit(parsed,depth+1,decode+1,key,true);return count===before?s:JSON.stringify(result);}
  }
  const n=/\\u[0-9a-f]{4}|\x1b\[/i.test(s)?normalized(s):null,t=n?.text??s;const spans=[];
  for(const m of ipMatches(t)){budget();if(matches(m.ip)){if(key)throw Error('redaction.sensitive-key');spans.push(m);if(spans.length>10000)throw Error('redaction.match-limit');}}
  if(!spans.length)return s;
  if(decode<limits.maxNestedJsonDecodes&&malformedJson.test(s))throw Error('redaction.unsupported');
  if(!redactableText(t,spans,structured,budget))throw Error('redaction.unsupported');
  count+=spans.length;let out='',at=0;
  for(const m of spans){
   budget();const start=n?n.starts[m.start]:m.start;
   out+=s.slice(at,start)+labels.get(m.ip);at=n?n.ends[m.end-1]:m.end;
  }
  return out+s.slice(at);
 }
 function visit(v,depth=0,decode=0,key=false,structured=false){
  budget();if(++nodes>limits.maxNodes||depth>limits.maxDepth)throw Error('inspection.structure-limit');
  if(typeof v==='string')return text(v,depth,decode,key,structured);
  if(v===null||['boolean','number','undefined'].includes(typeof v))return v;
  if(typeof v!=='object'||seen.has(v))throw Error('redaction.unsupported');seen.add(v);
  if(v.type&&['image','audio','video','document','base64','resource_link'].includes(v.type)||v.base64!==undefined)throw Error('redaction.unsupported');
  const out=Array.isArray(v)?[]:{};
  for(const [k,x] of Object.entries(v)){
   text(k,depth,decode,true,true);
   // Object wrapper fields stdout/stderr/text contain free text, not data scalars.
   const data=structured||!['stdout','stderr','text','result','content','context'].includes(k);
   Object.defineProperty(out,k,{value:visit(x,depth+1,decode,false,data),enumerable:true,writable:true,configurable:true});
  }
  seen.delete(v);return out;
 }
 const result=visit(value);budget();return {value:result,count};
}
