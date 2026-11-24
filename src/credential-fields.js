// Candidate names must end in a credential role. Splitting complete words
// keeps DB_PASSWORD / serviceApiToken while rejecting notpassword and metadata
// such as token_count / password_label. No XML or error-name special cases.
function fieldWords(name) {
  if(!name||name.length>256)return [];
  const leaf=name.split('.').at(-1).replace(/^--/,'').replace(/\?$/,'').replace(/^["']|["']$/g,'');
  return leaf.replace(/([A-Z]+)([A-Z][a-z])/g,'$1_$2').replace(/([a-z0-9])([A-Z])/g,'$1_$2').toLowerCase().split(/[_-]+/).filter(Boolean);
}

export function credentialFieldKind(name) {
  const words=fieldWords(name);
  const last=words.at(-1),prior=words.at(-2);
  if(['apikey','accesskey','privatekey','secretkey','accesstoken','refreshtoken','clientsecret'].includes(last))return 'token';
  if(last==='password'||last==='passwd')return 'password';
  if(last==='token'&&!['max','min','num','total'].includes(prior))return 'token';
  if(last==='secret'||last==='authorization'||last==='key'&&['api','private','secret','access'].includes(prior))return 'token';
  return null;
}
