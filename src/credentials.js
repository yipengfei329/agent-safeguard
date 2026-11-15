// Bounded, local syntax heuristics. This is not a full source-language parser.
// Data fields stay strict; code exemptions apply only to a single RHS, never a file/line.
const fields = '(?:password|passwd|access[_-]?token|refresh[_-]?token|token|api[_-]?key|client[_-]?secret|secret|authorization)';
const types = '(?:(?:Swift\\.)?(?:Bool|String|Int|Int32|Int64|UInt|UInt32|UInt64|Double|Float)|(?:Foundation\\.)?Data|boolean|string|number|bool|str|bytes)';
const declaration = new RegExp('(\\b(?:var|let|const)[ \\t]+'+fields+')[ \\t]*:[ \\t]*('+types+')(\\?|\\[\\])?([ \\t]*\\|[ \\t]*null)?(?=[ \\t]*(?:[=;{},)\\r\\n]|$))', 'gi');
const field = new RegExp('(?<![\\w$.-])(?:--)?(?:(?:[A-Za-z_$][\\w$]*\\.)*(?:'+fields+')|(["\\\'])'+fields+'\\1)(?![\\w$.-])[ \\t]*\\??[ \\t]*(:|=(?!=|>))', 'gi');
const credentialKey = new RegExp('^'+fields+'$', 'i');
const privateKey = /-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/;
const credentialURL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:]+:([^\s/@]+)@/gi;
// Deliberately specific formats, not generic entropy or every "sk-" identifier.
const signature = /\b(?:sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,})\b/;
const nullValue = /^(?:true|false|null|nil|undefined|None|True|False)(?=$|[\s,;})])/;
const reference = /^(?:\$\{[A-Za-z_][\w.:-]*\}|\$[A-Za-z_][\w]*|\{\{[ \t]*[\w.]+[ \t]*\}\})$/;
const redacted = /^(?:\*{3,}|\[REDACTED\]|<redacted>|<masked>|<PASSWORD>|<TOKEN>|<API_KEY>)$/i;
const typePrefix = new RegExp('^'+types+'(?:\\?|\\[\\])?(?:[ \\t]*\\|[ \\t]*null)?(?=[ \\t]*(?:[=;,})\\r\\n]|$))', 'i');
const codeRHS = /^(?:[A-Za-z_$][\w$]*(?:[?.][A-Za-z_$][\w$]*)*(?:\([^\r\n]*|(?:\[[^\r\n]*))?|[A-Za-z_$][\w$]*[ \t]*(?:===?|!==?|&&|\|\||\?)[^\r\n]*)/;

function placeholder(value) {
  return reference.test(value) || redacted.test(value);
}
// A sensitive field name is a hint, not proof. Deliberately allow ambiguous
// short values and code/schema symbols. Provider formats are checked separately.
function secretValue(value, name='') {
  value=value.trim();
  if(value.length<8||placeholder(value)||/^(?:changeme|change_me|placeholder|redacted|your[_ -](?:api[_ -]?key|password|token|secret)(?:[_ -]here)?|insert[_ -](?:api[_ -]?key|password|token|secret)[_ -]here)$/i.test(value))return false;
  if(/^(?:true|false|null|nil|undefined|None|Bool|String|boolean|string|number)$/i.test(value))return false;
  if(/^[A-Za-z][a-z]{2,}(?:[A-Z][a-z]{2,})+$/.test(value))return false;
  if(/^[A-Za-z_$][\w$]*(?:[?.][A-Za-z_$][\w$]*)+(?:\([^\r\n]*\))?$/.test(value)||/^[A-Za-z_$][\w$]*\([^\r\n]*\)$/.test(value))return false;
  // Types and deferred substitutions are not concrete secret values.
  if(/^(?:&(?:'[A-Za-z_]\w*[ \t]+)?(?:mut[ \t]+)?)?[A-Za-z_]\w*(?:::\w+)*(?:<[^=\r\n]+>)?(?:\[\]|\?)?$/.test(value)&&/[<>&?:]/.test(value))return false;
  if(/\$\{[^}]+\}|\{\{[^}]+\}\}/.test(value))return false;
  const password=/pass(?:word|wd)/i.test(name);
  // Prose under a token field is not token material. Wrapped opaque values
  // remain supported, but do not join arbitrary sentences into a credential.
  if(/[ \t]/.test(value)&&!password)return false;
  const sample=value.replace(/[\r\n]/g,'').slice(0,256);
  const categories=Number(/[a-z]/.test(sample))+Number(/[A-Z]/.test(sample))+Number(/[0-9]/.test(sample))+Number(/[^a-zA-Z0-9\s]/.test(sample));
  const counts=new Map();for(const c of sample)counts.set(c,(counts.get(c)||0)+1);
  let entropy=0;for(const count of counts.values()){const p=count/sample.length;entropy-=p*Math.log2(p);}
  return password&&sample.length>=8&&categories>=3&&entropy>=2.5 ||
    sample.length>=12&&categories>=2&&/[0-9\W_]/.test(sample)&&entropy>=3 ||
    sample.length>=24&&entropy>=3.5;
}
function readQuoted(text) {
  const quote = text[0];
  if (!['"', "'", '`'].includes(quote)) return null;
  let value = '', escaped = false;
  for (let i=1; i<text.length; i++) {
    const c=text[i];
    if (!escaped && c===quote) return value;
    if (!escaped && c==='\\') {escaped=true;value+=c;continue;}
    value+=c;escaped=false;
  }
  // A truncated/unterminated value must not become a blanket exemption.
  return value;
}
function literalArgument(rhs, isValue) {
  // Transparent value containers only; getSecret("ENV_NAME") is not a secret.
  for(let depth=0;depth<4;depth++){
    const m=rhs.match(/^(?:Data\([ \t]*base64Encoded[ \t]*:|Buffer\.from\(|(?:String::from|String|bytes|Some|Ok|SecretString::new|Secret::new|Cow::Borrowed|Arc::new)\()[ \t]*/);
    if(!m)return false;
    rhs=rhs.slice(m[0].length);
    const value=readQuoted(rhs);if(value!==null)return isValue(value);
  }
  return false;
}

// Bounded recognition of type annotations, including Rust generics, lifetimes,
// references and qualified types. Only skip the annotation, never an initializer
// or adjacent field; this is not a whole-file exemption.
const typeRun=/[\w$ \t&*?|.]+/y;
function annotationEnd(rhs){
  if(!/^(?:[A-Za-z_$&]|\[|\()/.test(rhs))return null;
  const stack=[];let i=0;
  for(;i<rhs.length&&i<512;i++){
    typeRun.lastIndex=i;const run=typeRun.exec(rhs);
    if(run){i+=run[0].length-1;continue;}
    const c=rhs[i];
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

export function credentialReason(text, key = '', fieldsOnly = false, minimum = 4, matchers = null) {
  const fieldMatcher=matchers?.field||field, declarationMatcher=matchers?.declaration||declaration, keyMatcher=matchers?.key||credentialKey;
  let fieldName=key;
  const valuePresent = value => fieldsOnly ? value.trim().length >= minimum && !placeholder(value.trim()) : secretValue(value,fieldName);
  if (!fieldsOnly) {
  if (privateKey.test(text)) return 'private-key';
  if (signature.test(text)) return 'token-format';
  credentialURL.lastIndex=0;
  for (const m of text.matchAll(credentialURL)) if (!placeholder(m[1])) return 'url-password';
  }
  // A structured string under a sensitive key is actual data, not source code.
  if (keyMatcher.test(key) && valuePresent(text)) return 'structured-value';

  // Remove only explicit type annotations; keep the initializer and adjacent content.
  const input=text.replace(declarationMatcher, '$1');
  fieldMatcher.lastIndex=0;
  for (const m of input.matchAll(fieldMatcher)) {
    fieldName=m[0];
    const start=m.index+m[0].length;
    // Bound context work even for minified/generated code on one long line.
    const before=input.slice(Math.max(0,m.index-256),m.index);
    const prefix=before.slice(before.lastIndexOf('\n')+1);
    // A quoted switch label is not a field. Exact boundaries already exclude ask-secret.
    if (/\bcase[ \t]+$/.test(prefix)) continue;
    let rhs=input.slice(start,start+1024).replace(/^[ \t]+/,'');
    if (/^\r?\n/.test(rhs)) {
      // Multiline assignments/YAML values require an indented or explicitly quoted
      // next line. Never join a grep filename/line-number prefix into a value.
      const next=rhs.match(/^\r?\n([ \t]*)([^\r\n]*)/);
      if (!next || (!next[1] && !/^["'`]/.test(next[2]))) continue;
      rhs=rhs.replace(/^\r?\n[ \t]*/,'');
      if (/^(?:[^\s:]+[\/\\][^\s:]*|[^\s:]+\.[A-Za-z]+):\d+[:\-]/.test(rhs)) continue;
    }
    if (!rhs || /^[\r\n;,}]/.test(rhs)) continue;
    if (m[2]===':' && /^[|>][+-]?[ \t]*(?:\r?\n|$)/.test(rhs)) {
      const block=rhs.match(/^[|>][+-]?[ \t]*\r?\n((?:[ \t]+[^\r\n]*(?:\r?\n|$))+)/);
      if (block && valuePresent(block[1])) return 'block-scalar';
      continue;
    }
    const isCode=/\b(?:var|let|const|val)[ \t]+$/.test(prefix) || /(?:\{|,)[ \t]*$/.test(prefix) ||
      /\b(?:pub(?:\([^()\r\n]*\))?|public|private|protected|readonly|static)[ \t]+$/.test(prefix) ||
      /\b(?:fn|function|func|def)\b[^\r\n]*\([^)]*$/.test(prefix) ||
      /\.(?:go|swift|[cm]?[jt]sx?|py|rs):\d+:/.test(prefix) ||
      /\./.test(m[0].split(/[:=]/,1)[0]) ||
      /\b(?:struct|interface|class|enum|trait)\b[^{}]{0,120}\{[^{}]*$/.test(before);
    // Common generated-code members need no quoted-value/type parsing. This
    // excludes calls, string initializers and typed assignments with a single =.
    if (isCode && /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*[ \t]*(?:[,;}]|$|===?|!==?)/.test(rhs)) continue;
    const end=m[2]===':'&&!m[1]&&isCode?annotationEnd(rhs):null;
    if(end!==null){
      const rest=rhs.slice(end).trimStart();
      if(!/^=(?!=|>)/.test(rest))continue;
      rhs=rest.slice(1).trimStart();
    }
    const annotation=rhs.match(typePrefix);
    if (m[2]===':' && annotation && (isCode || /^[ \t]*;/.test(rhs.slice(annotation[0].length)))) {
      const rest=rhs.slice(annotation[0].length).trimStart();
      if (!/^=(?!=|>)/.test(rest)) continue;
      rhs=rest.slice(1).trimStart();
    }
    if ((isCode || m[2]===':') && /^(?:#|\/\/)/.test(rhs)) continue;
    const quoted=readQuoted(rhs);
    if (quoted!==null) {
      const rest=rhs.slice(quoted.length+2);
      if (/^(?:Bearer|Basic) $/.test(quoted) && /^[ \t]*\+[ \t]*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*[ \t]*(?:;|$)/.test(rest)) continue;
      if (/^(?:Bearer|Basic) \$\{[A-Za-z_$][\w$.]*\}$/.test(quoted)) continue;
      let combined=quoted,tail=rest;
      for(let i=0;i<8;i++){
        const join=tail.match(/^[ \t]*\+[ \t]*(?=["'`])/);if(!join)break;
        tail=tail.slice(join[0].length);const part=readQuoted(tail);if(part===null)break;
        combined+=part;tail=tail.slice(part.length+2);
      }
      if(valuePresent(combined)||/^(?:Bearer|Basic) /.test(combined)&&valuePresent(combined.replace(/^(?:Bearer|Basic) /,'')))return 'literal-value';continue;
    }
    const newline=rhs.indexOf('\n');
    const firstLine=newline<0?rhs:rhs.slice(0,newline);
    if ((isCode || m[1]) && nullValue.test(firstLine)) continue;
    // An object is not an opaque value. Nested credential fields are matched
    // independently, and JSON/structured values are traversed by the core.
    if (!fieldsOnly && /^\{/.test(firstLine)) continue;
    if (/^(?:\$\{[A-Za-z_][\w.:-]*\}|\$[A-Za-z_][\w]*|\{\{[ \t]*[\w.]+[ \t]*\}\})(?=$|[\s,;}])/.test(firstLine)) continue;
    const value=firstLine.match(/^[^\s,;}]+/)?.[0] ?? '';
    if (placeholder(value)) continue;
    if (/^(?:Bearer|Basic)[ \t]+/i.test(firstLine)) {
      const remainder=firstLine.replace(/^(?:Bearer|Basic)[ \t]+/i,'').trim();
      if(placeholder(remainder))continue;
      const auth=remainder.split(/[\s,;}]/,1)[0];
      if (valuePresent(auth)) return 'authorization-value';
      continue;
    }
    // Recognize an expression, not an unquoted arbitrary value in an env/log file.
    // Dotted references, calls and comparisons are unambiguous enough on their own.
    const expression=/^[A-Za-z_$][\w$]*[ \t]*(?:===?|!==?|&&|\|\|)/.test(firstLine);
    if (literalArgument(firstLine,valuePresent)) return 'encoded-literal';
    if ((isCode || expression) && codeRHS.test(firstLine)) continue;
    if (valuePresent(value)) return 'unquoted-value';
  }
  return null;
}

export function hasCredentials(text, key = '') {
  return credentialReason(text,key)!==null;
}

export function createAssignmentDetector(names, minimum) {
  const matchers={field:new RegExp(field.source.replaceAll(fields,names),'gi'),declaration:new RegExp(declaration.source.replaceAll(fields,names),'gi'),key:new RegExp('^'+names+'$','i')};
  return (text,key='')=>credentialReason(text,key,true,minimum,matchers)!==null;
}
