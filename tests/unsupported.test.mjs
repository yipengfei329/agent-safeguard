import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
const image={type:'image',source:{type:'base64',media_type:'image/png',data:'A'.repeat(5*1024*1024)}};
test('unsupported binary contents pass by default without decoding or counting blob bytes',()=>{
 const e=compile();
 for(const value of [image,{type:'audio',data:'AAAA'},{type:'document',source:{type:'base64',media_type:'application/pdf',data:'AAAA'}},{mimeType:'application/octet-stream',base64:'AAAA'},{type:'resource_link',uri:'https://example.invalid/file'}])assert.equal(e.scan(value).blocked,false);
});
test('binary block never exempts adjacent text or metadata',()=>{
 const e=compile();
 for(const content of [[image,{type:'text',text:'password=SYNTHETIC_PASSWORD'}],[{type:'text',text:'203.0.113.7'},image]])assert.equal(e.scan({content}).blocked,true);
 assert.equal(e.scan({...image,caption:'token=SYNTHETIC_TOKEN'}).rule,'security.credentials');
 assert.equal(e.scan({type:'resource_link',uri:'https://203.0.113.7/file'}).rule,'network.address');
});
test('strict unsupported policy remains selectable',()=>{
 const cfg=structuredClone(defaults);cfg.policy.onUnsupportedContent='block';
 assert.equal(compile(cfg).scan(image).rule,'inspection.failed');
});
test('allowing opaque payloads does not allow scan errors or text limits',()=>{
 const e=compile(),cycle={};cycle.self=cycle;
 for(const value of [cycle,{content:[image,{type:'text',text:'x'.repeat(4194305)}]}])assert.equal(e.scan(value).rule,'inspection.failed');
});
