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
function valuePresent(value) {
  value = value.trim();
  return value.length >= 4 && !placeholder(value);
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
function literalArgument(rhs) {
  const m=rhs.match(/^(?:Data\([ \t]*base64Encoded[ \t]*:|Buffer\.from\(|(?:String|bytes)\()[ \t]*(["'`][\s\S]*)/);
  return m && valuePresent(readQuoted(m[1]) ?? '');
}

export function credentialReason(text, key = '', fieldsOnly = false, minimum = 4, matchers = null) {
  const fieldMatcher=matchers?.field||field, declarationMatcher=matchers?.declaration||declaration, keyMatcher=matchers?.key||credentialKey;
  const valuePresent = value => value.trim().length >= minimum && !placeholder(value.trim());
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
      /\b(?:public|private|protected|readonly|static)[ \t]+$/.test(prefix) ||
      /\b(?:function|func|def)\b[^\r\n]*\([^)]*$/.test(prefix) ||
      /\.(?:go|swift|[cm]?[jt]sx?|py|rs):\d+:/.test(prefix) ||
      /\./.test(m[0].split(/[:=]/,1)[0]);
    // Common generated-code members need no quoted-value/type parsing. This
    // excludes calls, string initializers and typed assignments with a single =.
    if (isCode && /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*[ \t]*(?:[,;}]|$|===?|!==?)/.test(rhs)) continue;
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
      if(valuePresent(quoted))return 'literal-value';continue;
    }
    const newline=rhs.indexOf('\n');
    const firstLine=newline<0?rhs:rhs.slice(0,newline);
    if ((isCode || m[1]) && nullValue.test(firstLine)) continue;
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
    if (literalArgument(firstLine)) return 'encoded-literal';
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
