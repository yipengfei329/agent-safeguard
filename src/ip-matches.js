import ipaddr from 'ipaddr.js';
// The same boundaries serve both blocking and transformation. Offsets are UTF-16.
const pattern=/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.[\w.])|(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:.]*(?:%[\w.-]+)?(?![\w:%])/g;
export function* ipMatches(text){
 for(const m of text.matchAll(pattern)){
  const value=m[0].replace(/\.+$/,'');
  try{if(ipaddr.isValid(value))yield {start:m.index,end:m.index+value.length,ip:ipaddr.parse(value)};}catch{}
 }
}
export function canonicalIP(ip){return (ip.kind()==='ipv6'&&ip.isIPv4MappedAddress()?ip.toIPv4Address():ip).toString().replace(/%.+$/,'');}
