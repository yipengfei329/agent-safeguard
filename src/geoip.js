import snapshot from '../data/geoip-country.js';

const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const invalid=()=>{throw Error('INVALID_GEOIP_DATABASE');};
function compare(data,offset,words){
  for(let j=0;j<words.length;j++){
    if(data[offset+j]<words[j])return -1;
    if(data[offset+j]>words[j])return 1;
  }
  return 0;
}
// Portable to Mods and QuickJS: no Buffer, filesystem, network, or host APIs.
export function createGeoIP(envelope){
  if(!envelope||envelope.schema!==1||envelope.format!=='cn-other-unknown-u32le-v1'||
    !/^\d{4}-\d{2}$/.test(envelope.month)||! /^[a-f0-9]{64}$/.test(envelope.sourceSha256)||
    !Array.isArray(envelope.counts)||envelope.counts.length!==2||
    !envelope.counts.every(n=>Number.isInteger(n)&&n>0&&n<=100000)||
    typeof envelope.payload!=='string'||envelope.payload.length>900000||
    !Number.isInteger(envelope.checksum)||envelope.checksum<0||envelope.checksum>0xffffffff)invalid();
  const length=(envelope.counts[0]*3+envelope.counts[1]*9)*4;
  const s=envelope.payload;
  if(length>675000||s.length!==Math.ceil(length/3)*4||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))invalid();
  const bytes=new Uint8Array(length);let at=0,hash=2166136261;
  for(let i=0;i<s.length;i+=4){
    const a=alphabet.indexOf(s[i]),b=alphabet.indexOf(s[i+1]),c=s[i+2]==='='?0:alphabet.indexOf(s[i+2]),d=s[i+3]==='='?0:alphabet.indexOf(s[i+3]);
    const n=(a<<18)|(b<<12)|(c<<6)|d;
    for(const shift of [16,8,0])if(at<length){const v=(n>>>shift)&255;bytes[at++]=v;hash=Math.imul(hash^v,16777619)>>>0;}
  }
  if(hash!==envelope.checksum)invalid();
  const view=new DataView(bytes.buffer),tables=[];let offset=0;
  for(const [k,n] of [1,4].entries()){
    const stride=n*2+1,data=new Uint32Array(envelope.counts[k]*stride);
    for(let i=0;i<data.length;i++,offset+=4)data[i]=view.getUint32(offset,true);
    for(let i=0;i<data.length;i+=stride){
      const start=data.subarray(i,i+n);
      if(compare(data,i+n,start)<0||data[i+n*2]>2||i>0&&compare(data,i-stride+n,start)>=0)invalid();
    }
    tables.push(data);
  }
  const metadata=Object.freeze({provider:'DB-IP Country Lite',month:envelope.month,sourceSha256:envelope.sourceSha256,country:'CN',onUnknown:'allow'});
  return Object.freeze({metadata,lookup(ip){
    if(ip.kind()==='ipv6'&&ip.isIPv4MappedAddress())ip=ip.toIPv4Address();
    const octets=ip.toByteArray(),words=[];
    for(let i=0;i<octets.length;i+=4)words.push((octets[i]*16777216+octets[i+1]*65536+octets[i+2]*256+octets[i+3])>>>0);
    const n=words.length,data=tables[n===1?0:1],stride=n*2+1;let lo=0,hi=data.length/stride-1;
    while(lo<=hi){const mid=(lo+hi)>>>1,off=mid*stride;
      if(compare(data,off,words)>0)hi=mid-1;
      else if(compare(data,off+n,words)<0)lo=mid+1;
      else return data[off+n*2];
    }
    return 0;
  }});
}
let cached;
export function bundledGeoIP(){return cached??=createGeoIP(snapshot);}
