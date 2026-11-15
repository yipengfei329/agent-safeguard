// Syntax evidence only, never a vocabulary of repository/provider/test names.
// An uppercase identifier by itself is ambiguous: callers may use this only
// when the extractor has established an explicit name-declaration context.
const name=/^_*[A-Z][A-Z0-9]*(?:_+[A-Z0-9]+)+_*$/;
export function symbolName(value){return value.length<=128&&name.test(value);}
// A complete member/index access denotes a reference. Indexes must themselves
// be identifiers, not arbitrary quoted text that could contain a credential.
// Requiring the entire value avoids exempting literal prefixes or suffixes.
const reference=/^[A-Za-z_$][\w$]*(?:(?:\??\.[A-Za-z_$][\w$]*)|(?:\[(?:"[A-Za-z_][\w]*"|'[A-Za-z_][\w]*'|[A-Z_][A-Z0-9_]*)\]))+$/;
export function symbolReference(value){
  if(value.length>256||!reference.test(value))return false;
  // Quoted indexes can carry arbitrary data. Only admit short identifiers or
  // explicit constant-name shapes here; otherwise let value/atom detection
  // inspect the string instead of discarding all of its literal material.
  for(const match of value.matchAll(/\[["']([A-Za-z_][\w]*)["']\]/g)){
    if(match[1].length>=8&&!symbolName(match[1]))return false;
  }
  return true;
}
