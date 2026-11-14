// Recognize explicit variable declarations without exempting the enclosing text.
// This is a bounded syntax heuristic, not a language parser or arbitrary secret detector.
const fields = '(?:password|passwd|access[_-]?token|refresh[_-]?token|token|api[_-]?key|client[_-]?secret|secret|authorization)';
const types = '(?:(?:Swift\\.)?(?:Bool|String|Int|Int32|Int64|UInt|UInt32|UInt64|Double|Float)|(?:Foundation\\.)?Data|boolean|string|number|bool|str|bytes)';
const declaration = new RegExp('(\\b(?:var|let|const)[ \\t]+'+fields+')[ \\t]*:[ \\t]*('+types+')(\\?|\\[\\])?([ \\t]*\\|[ \\t]*null)?(?=[ \\t]*(?:[=;{},)\\r\\n]|$))([ \\t]*=[ \\t]*(?:false|true|null|nil|undefined|Data\\(\\)|String\\(\\))(?=[ \\t]*(?://|[;,}\\r\\n]|$)))?', 'gi');
const fieldValue = new RegExp('\\b'+fields+'\\s*["\']?\\s*[:=]\\s*["\']?[^\\s"\',;}]{4,}', 'i');
const credentialKey = new RegExp('^'+fields+'$', 'i');
const privateKeyOrURL = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b[a-z][a-z0-9+.-]*:\/\/[^\s/:]+:[^\s/@]+@/i;

export function hasCredentials(text, key = '') {
  // Structured values are data, even when a password happens to be a type name.
  if (credentialKey.test(key) && fieldValue.test(key+': '+text)) return true;
  if (privateKeyOrURL.test(text)) return true;
  const values = text.replace(declaration, (_, name, type, suffix, nullable, initializer = '') => {
    const value = initializer.replace(/^[ \t]*=[ \t]*/, '');
    const emptyBoolean = /^(?:Swift\.)?Bool$|^boolean$|^bool$/.test(type) && /^(?:false|true)$/.test(value);
    const emptyNullable = (suffix === '?' || nullable) && /^(?:null|nil|undefined)$/.test(value);
    const emptyConstructor = /^(?:Foundation\.)?Data$/.test(type) && value === 'Data()' || /^(?:Swift\.)?String$/.test(type) && value === 'String()';
    return name + (emptyBoolean || emptyNullable || emptyConstructor ? '' : initializer);
  });
  return fieldValue.test(values);
}
