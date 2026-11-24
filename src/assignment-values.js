import {placeholder,readQuoted,readSourceQuoted} from './value-syntax.js';
import {typeFieldOffsets} from './type-context.js';
// Every field-based rule uses this extractor. Policies receive only values
// admitted by the same syntax checks; no identity-specific arbitrary-text path.
const fields='(?:[A-Za-z_$][\\w$-]*)';
const types='(?:(?:Swift\\.)?(?:Bool|String|Int|Int32|Int64|UInt|UInt32|UInt64|Double|Float)|(?:Foundation\\.)?Data|boolean|string|number|bool|str|bytes)';
const field = new RegExp('(?<![\\w$.-])(?:--)?(?:(?:[A-Za-z_$][\\w$]*\\.)*(?:'+fields+')|(["\\\'])'+fields+'\\1)(?![\\w$.-])[ \\t]*\\??[ \\t]*(:=|:|=(?!=|>))', 'gi');
export function assignmentMatchers(names=fields,marker=null) {
  return {field:new RegExp(field.source.replaceAll(fields,names),'gi'),key:new RegExp('^'+names+'$','i'),marker};
}
const nullValue = /^(?:true|false|null|nil|undefined|None|True|False)(?=$|[\s,;})])/;
const typePrefix = new RegExp('^'+types+'(?:\\?|\\[\\])?(?:[ \\t]*\\|[ \\t]*null)?(?=[ \\t]*(?:[=;,})\\r\\n]|$))', 'i');
const codeRHS = /^(?:[A-Za-z_$][\w$]*(?:[?.][A-Za-z_$][\w$]*)*(?:\([^\r\n]*|(?:\[[^\r\n]*))?|[A-Za-z_$][\w$]*[ \t]*(?:===?|!==?|&&|\|\||\?)[^\r\n]*)/;
const expressionStart=/^(?:(?:await|try|new|yield|lambda|async|return|throw)[ \t]+\S|[A-Za-z_$][\w$]*(?:[?.][A-Za-z_$][\w$]*)*\s*[([])/;
const memberReference=/^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+(?=$|[\s,;})])/;
const dynamicTail=/^[ \t]*(?:[+?]|\?\.|\.(?:[A-Za-z_]\w*)\s*\(|(?:if|and|or)\b)/;
const interpolation=/\$\{|\{\{|\\\(/;

function literalArgument(rhs, isValue) {
  // Transparent value containers only; getSecret("ENV_NAME") is not a secret.
  for(let depth=0;depth<4;depth++){
    const m=rhs.match(/^(?:Data\([ \t]*base64Encoded[ \t]*:|Buffer\.from\(|(?:(?:[A-Za-z_]\w*\.)*string|\.string|\.some|String::from|String|bytes|Some|Ok|SecretString::new|Secret::new|Cow::Borrowed|Arc::new)\()[ \t]*/);
    if(!m)return false;
    rhs=rhs.slice(m[0].length);
    const value=readSourceQuoted(rhs);if(value!==null)return isValue(value.value);
  }
  return false;
}

// Positive recognition of a complete unquoted configuration/log scalar. Do not
// slice a token out of an arbitrary expression and measure its punctuation as
// entropy. Quoted strings, structured fields and explicit formats have their
// own paths, so unknown syntax can safely abstain here without skipping later
// fields in the same result. Restricted alphabet intentionally trades coverage
// of exotic unquoted passwords for fewer false positives.
function bareScalarValue(rhs){
  const match=rhs.match(/^((?=[A-Za-z0-9_#]|\$\{|\{\{)(?:[A-Za-z0-9_+/.!@#%=-]|\$\{[A-Za-z_][\w.:-]*\}|\{\{[ \t]*[\w.]+[ \t]*\}\})+)(?=$|[\s,;}])/);
  if(!match)return null;
  const tail=rhs.slice(match[0].length);
  if(!/^[ \t]+\*\//.test(tail)&&/^[ \t]+(?:[?!&|+*/=<>.\[(]|->|(?:as|instanceof|if|else|and|or|is|in|not)\b)/.test(tail))return null;
  return match[1];
}

// Bounded recognition of type annotations, including Rust generics, lifetimes,
// references and qualified types. Only skip the annotation, never an initializer
// or adjacent field; this is not a whole-file exemption.
const typeRun=/[\w$ \t&*?|.]+/y;
function annotationEnd(rhs, allowString=false){
  if(!/^(?:[A-Za-z_$&]|\[|\()/.test(rhs)&&!(allowString&&/^["'`]/.test(rhs)))return null;
  const stack=[];let i=0;
  for(;i<rhs.length&&i<512;i++){
    typeRun.lastIndex=i;const run=typeRun.exec(rhs);
    if(run){i+=run[0].length-1;continue;}
    const c=rhs[i];
    const lifetime=c==="'"&&/^'[A-Za-z_]\w*(?=[\s,>+])/.test(rhs.slice(i));
    if(allowString&&!lifetime&&/["'`]/.test(c)){
      const quoted=readQuoted(rhs.slice(i));if(!quoted?.complete)return null;
      i+=quoted.length-1;continue;
    }
    if(!stack.length&&/[=,;})\r\n]/.test(c))break;
    if('(<['.includes(c))stack.push(c);
    else if(')>]'.includes(c)){if(stack.pop()!=={')':'(',']':'[','>':'<'}[c])return null;}
    else if(c===':'&&rhs[i+1]===':')i++;
    else if(c==="'"){const lifetime=rhs.slice(i).match(/^'[A-Za-z_]\w*(?![\w'])/);if(!lifetime)return null;i+=lifetime[0].length-1;}
    else if(!/[\s,;]/.test(c))return null;
  }
  if(stack.length||i>=512||!/[A-Za-z_]/.test(rhs.slice(0,i)))return null;
  return i;
}


export function assignmentReason(text,key,policy,budget=()=>{},syntax) {
  const {field:fieldMatcher,key:keyMatcher,marker}=policy.matchers;
  let fieldName=keyMatcher.test(key)?policy.classify(key):null;
  const negativeValues=new Map();
  const fieldKinds=new Map(),prefixContexts=new Map();
  const valuePresent=value=>{
    let cache=negativeValues.get(fieldName);
    if(!cache){cache=new Set();negativeValues.set(fieldName,cache);}
    if(value.length<=256&&cache.has(value))return false;
    const result=policy.accept(value,fieldName,budget);
    if(!result&&value.length<=256&&cache.size<128)cache.add(value);
    return result;
  };
  const literalPresent=value=>(policy.allowDynamic!==false||!interpolation.test(value))?valuePresent(value):false;
  function quotedReason(rhs) {
    const quoted=readSourceQuoted(rhs);
    if (quoted!==null) {
      const rest=rhs.slice(quoted.length);
      if (/^(?:Bearer|Basic) $/.test(quoted.value) && /^[ \t]*\+[ \t]*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*[ \t]*(?:;|$)/.test(rest)) return null;
      if (/^(?:Bearer|Basic) \$\{[A-Za-z_$][\w$.]*\}$/.test(quoted.value)) return null;
      let combined=quoted.value,tail=rest;
      for(let i=0;i<8;i++){
        const join=tail.match(/^[ \t]*\+[ \t]*(?=["'`])/);if(!join)break;
        tail=tail.slice(join[0].length);const part=readQuoted(tail);if(part===null)break;
        combined+=part.value;tail=tail.slice(part.length);
      }
      if(policy.allowDynamic===false&&dynamicTail.test(tail))return null;
      if(literalPresent(combined)||/^(?:Bearer|Basic) /.test(combined)&&literalPresent(combined.replace(/^(?:Bearer|Basic) /,'')))return 'literal-value';return null;
    }
    return undefined;
  }
  function candidateReason(m,start,before,rawRHS) {
    // Bound context work even for minified/generated code on one long line.
    const prefix=before.slice(before.lastIndexOf('\n')+1);
    // A quoted switch label is not a field. Exact boundaries already exclude ask-secret.
    if (/\bcase[ \t]+$/.test(prefix)) return null;
    let rhs=rawRHS.replace(/^[ \t]+/,'');
    if (/^\r?\n/.test(rhs)) {
      // Multiline assignments/YAML values require an indented or explicitly quoted
      // next line. Never join a grep filename/line-number prefix into a value.
      const next=rhs.match(/^\r?\n([ \t]*)([^\r\n]*)/);
      if (!next || (!next[1] && !/^["'`]/.test(next[2]))) return null;
      rhs=rhs.replace(/^\r?\n[ \t]*/,'');
      if (/^(?:[^\s:]+[\/\\][^\s:]*|[^\s:]+\.[A-Za-z]+):\d+[:\-]/.test(rhs)) return null;
    }
    if (!rhs || /^[\r\n;,}]/.test(rhs)) return null;
    // In shell/config assignments, whitespace followed by NAME= starts a new
    // field, not the previous field's value. Do not consume that next match.
    // Quotes retain their literal meaning: PASSWORD="NAME=value" is a value.
    if(m[2]==='='&&!m[1]&&/\S=$/.test(m[0])&&/^\s/.test(input[start]||'')&&/^[A-Za-z_][\w]*=(?!=)/.test(rhs))return null;
    if (m[2]===':' && /^[|>][+-]?[ \t]*(?:\r?\n|$)/.test(rhs)) {
      const block=rhs.match(/^[|>][+-]?[ \t]*\r?\n((?:[ \t]+[^\r\n]*(?:\r?\n|$))+)/);
      if (block && valuePresent(block[1])) return 'block-scalar';
      return null;
    }
    // Explicit assignment plus a literal cannot be a type annotation. Evaluate
    // its complete value/concatenation before constructing code-prefix context.
    // The same parser handles the slower annotated/colon path below.
    if(m[2]==='='&&/^["'`rRuUbB]/.test(rhs)){
      const result=quotedReason(rhs);
      if(result!==undefined){if(result)return result;return null;}
    }
    // An explicit declaration assigning a member reference contains no literal
    // value. Restrict this shortcut to a clean declaration prefix so dotted
    // hostnames in configuration and comments still reach the value policy.
    if(m[2]==='='&&/^[ \t]*(?:const|let|var|val)[ \t]+$/.test(prefix)&&memberReference.test(rhs))return null;
    // A call / await / constructor expression is explicit even in an isolated
    // Python line with no declaration keyword. Only transparent literal
    // containers can provide a value; nested fields are matched separately.
    if(expressionStart.test(rhs)){
      if(literalArgument(rhs,literalPresent))return 'encoded-literal';
      return null;
    }
    // Memoize only prefix syntax, never a value or an allow/block decision.
    // Qualified names and multiline struct context still use this occurrence.
    let context=prefixContexts.get(prefix);
    if(!context){
      const inComment=/\/\/[^\r\n]*$|\/\*[^\r\n]*$|(?:^|[ \t])#[^\r\n]*$|^[ \t]*\*/.test(prefix);
      const explicitType=/\b(?:var|let|const|val)[ \t]+$/.test(prefix)||/\b(?:fn|function|func|def)\b[^\r\n]*\([^)]*$/.test(prefix);
      context={inComment,explicitType,code:explicitType||/(?:\{|,)[ \t]*$/.test(prefix)||
        /\b(?:pub(?:\([^()\r\n]*\))?|public|private|protected|readonly|static)[ \t]+$/.test(prefix)||
        /\.(?:go|swift|[cm]?[jt]sx?|py|rs):\d+:/.test(prefix)};
      if(prefixContexts.size<128)prefixContexts.set(prefix,context);
    }
    const {inComment,explicitType}=context;
    const indentedAssignment=m[2]==='='&&/^[+-]?[ \t]+$/.test(prefix);
    const spacedAssignment=m[2]==='='&&/[ \t]=$/.test(m[0])&&/^[ \t]/.test(input[start]||'');
    const isCode=!inComment&&(context.code || indentedAssignment || m[2]===':=' ||
      /\./.test(m[0].split(/[:=]/,1)[0]) ||
      /\b(?:struct|interface|class|enum|trait)\b[^{}]{0,120}\{[^{}]*$/.test(before));
    // Common generated-code members need no quoted-value/type parsing. This
    // excludes calls, string initializers and typed assignments with a single =.
    if (isCode && /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*[ \t]*(?:[,;}]|$|===?|!==?)/.test(rhs)) return null;
    const end=m[2]===':'&&!m[1]&&isCode?annotationEnd(rhs,explicitType):null;
    if(end!==null){
      const rest=rhs.slice(end).trimStart();
      if(!/^=(?!=|>)/.test(rest))return null;
      rhs=rest.slice(1).trimStart();
    }
    const annotation=rhs.match(typePrefix);
    if (m[2]===':' && annotation && (isCode || /^[ \t]*;/.test(rhs.slice(annotation[0].length)))) {
      const rest=rhs.slice(annotation[0].length).trimStart();
      if (!/^=(?!=|>)/.test(rest)) return null;
      rhs=rest.slice(1).trimStart();
    }
    if ((isCode || m[2]===':') && /^(?:#|\/\/)/.test(rhs)) return null;
    const quotedResult=quotedReason(rhs);
    if(quotedResult!==undefined){if(quotedResult)return quotedResult;return null;}
    const newline=rhs.indexOf('\n');
    const firstLine=newline<0?rhs:rhs.slice(0,newline);
    if (nullValue.test(firstLine)||/^(?:String|Bool|string|boolean|number|bool|str|bytes)(?=$|[\s,;})])/.test(firstLine)) return null;
    // An object is not an opaque value. Nested credential fields are matched
    // independently, and JSON/structured values are traversed by the core.
    if (/^[\[{]/.test(firstLine)) return null;
    if (/^(?:\$\{[A-Za-z_][\w.:-]*\}|\$[A-Za-z_][\w]*|\{\{[ \t]*[\w.]+[ \t]*\}\})(?=$|[\s,;}])/.test(firstLine)) return null;
    const value=firstLine.match(/^[^\s,;}]+/)?.[0] ?? '';
    if (placeholder(value)) return null;
    if (/^(?:Bearer|Basic)[ \t]+/i.test(firstLine)) {
      const remainder=firstLine.replace(/^(?:Bearer|Basic)[ \t]+/i,'').trim();
      if(placeholder(remainder))return null;
      const auth=remainder.split(/[\s,;}]/,1)[0];
      if (valuePresent(auth)) return 'authorization-value';
      return null;
    }
    // Recognize an expression, not an unquoted arbitrary value in an env/log file.
    // Dotted references, calls and comparisons are unambiguous enough on their own.
    const expression=/^[A-Za-z_$][\w$]*[ \t]*(?:===?|!==?|&&|\|\|)/.test(firstLine);
    if (literalArgument(firstLine,literalPresent)) return 'encoded-literal';
    if(expressionStart.test(rhs)||!inComment&&(isCode||spacedAssignment)&&memberReference.test(firstLine))return null;
    if ((isCode || expression) && codeRHS.test(firstLine)) return null;
    const concrete=bareScalarValue(firstLine);
    if (concrete!==null&&valuePresent(concrete)) return 'unquoted-value';
    return null;
  }
  // Structured strings are actual data. Do not reinterpret them as source code.
  if(fieldName&&valuePresent(text)){if(syntax?.recordLocation)syntax.match={offset:0,field:fieldName};return 'structured-value';}
  if(marker&&!marker.test(text))return null;
  // Interpret annotations at the field itself. Rewriting every declaration
  // first duplicated a full scan and changed offsets in large source output.
  const input=text;
  const negativeCandidates=new Set();let cacheMisses=0,cacheEnabled=true;
  fieldMatcher.lastIndex=0;
  if(!fieldMatcher.test(input))return null;
  const typeFields=typeFieldOffsets(input,budget,syntax);
  fieldMatcher.lastIndex=0;
  for (const m of input.matchAll(fieldMatcher)) {
    budget();
    if(m[2]===':'&&typeFields.has(m.index))continue;
    let field=null;
    if(fieldKinds.has(m[0]))field=fieldKinds.get(m[0]);
    else{
      const name=m[0].slice(0,m[0].lastIndexOf(m[2])).trim();
      field=policy.classify(name);
      if(m[0].length<=256&&fieldKinds.size<128)fieldKinds.set(m[0],field);
    }
    if(!field)continue;
    fieldName=field;
    const start=m.index+m[0].length;
    const before=input.slice(Math.max(0,m.index-256),m.index),rawRHS=input.slice(start,start+1024);
    // Memoize only an identical candidate and every byte of context the parser
    // reads. Type membership is checked above on each occurrence. Length framing
    // prevents delimiter collisions; no line/file or neighboring-field skip.
    const cacheKey=cacheEnabled&&m[0].length<=256?m[0].length+':'+m[0]+before.length+':'+before+rawRHS:null;
    if(cacheKey!==null&&negativeCandidates.has(cacheKey))continue;
    const result=candidateReason(m,start,before,rawRHS);
    if(result){if(syntax?.recordLocation)syntax.match={offset:m.index,field:fieldName};return result;}
    if(cacheKey!==null){
      if(negativeCandidates.size<128)negativeCandidates.add(cacheKey);
      // Non-repeating source should not pay per-candidate cache-key costs.
      else if(++cacheMisses>=128)cacheEnabled=false;
    }
  }
  return null;
}
