import test from 'node:test';import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {typeFieldOffsets} from '../src/type-context.js';
import {readQuoted} from '../src/value-syntax.js';
import {denseSource} from '../fixtures/dense-source.mjs';
const secret='pM8!sQ3_vL7#rD5-tN2@xK9';
test('repeated candidate checks cannot exempt a changed initializer or trailing secret',()=>{
 const engine=compile();const base=denseSource(100*1024);
 for(const tail of [`\nconst token="${secret}";`,`\nconst password="${secret}";`,`\nconst device_id="SYNTHETIC456789";`,`\nconst hostname="SyntheticHost";`])assert.equal(engine.scan(base+tail).blocked,true);
 const changed=base.replace('harbours-000000',secret);assert.equal(engine.scan(changed).rule,'security.credentials');
 assert.equal(engine.scan({stdout:base,stderr:'api_key='+secret}).rule,'security.credentials');
});
test('candidate cache cannot conflate role, multiline context, concatenation or raw strings',()=>{
 const e=compile();
 for(const code of [
  'token="Lanterns24680";\npassword="Lanterns24680";',
  'token="<binding:" + """\nslot>""";\ntoken="<binding:" + """\n'+secret+'>""";',
  'token="slot";\ntoken="slot" + "'+secret+'";',
  'token=r#"slot"#;\ntoken=r#"'+secret+'"#;',
  'interface Options { token: "'+secret+'"; }\nconst token = "'+secret+'";',
 ])assert.equal(e.scan(code).rule,'security.credentials');
});
test('type cache is tied to exact text and published only after completion',()=>{
 const context={};const text='interface Fields { token: string; }';
 const fields=typeFieldOffsets(text,()=>{},context);assert.ok(fields.size);
 assert.equal(typeFieldOffsets(text,()=>{throw Error('should reuse complete parse');},context),fields);
 assert.equal(typeFieldOffsets('const token="'+secret+'";',()=>{},context).size,0);
 const prior=context.text;assert.throws(()=>typeFieldOffsets(text,()=>{throw Error('budget');},context));assert.equal(context.text,prior);
});
test('native literal search preserves escaping and truncation semantics',()=>{
 for(const [source,value,length,complete] of [
  ['"abc" tail','abc',5,true],['"a\\"b" tail','a"b',6,true],
  ['"a\\u0041"','aA',9,true],['"abc','abc',4,false],
  ['"""a\nb""" tail','a\nb',9,true],
 ])assert.deepEqual(readQuoted(source),{value,length,complete});
});
test('sparse type lexer preserves header boundaries and opaque token interiors',()=>{
 for(const prefix of ['', 'export ', 'declare ', 'x; ', 'x+ ', 'x\n', 'export/* c */', 'x/*\nc */']){
  const text=prefix+'interface Fields { token: string; nested: { hostname: string; }; }';
  const fields=typeFieldOffsets(text);assert.ok(fields.has(text.indexOf('token:')));assert.ok(fields.has(text.indexOf('hostname:')));
 }
 for(const text of [
  '$export interface Fields { token: string; }',
  'x.interface Fields { token: string; }',
  '"interface Fields { token: string; }"',
  '/interface Fields { token: string; }/',
  'interface Fields { token: string;',
 ])assert.equal(typeFieldOffsets(text).has(text.indexOf('token:')),false);
 const text='interface Fields { /* token: string; */ note: "hostname: string;"; device_id: string; }';
 const fields=typeFieldOffsets(text);assert.equal(fields.has(text.indexOf('token:')),false);assert.equal(fields.has(text.indexOf('hostname:')),false);assert.ok(fields.has(text.indexOf('device_id:')));
});
test('type header search handles long whitespace gaps and resumes after ordinary source',()=>{
 const text='x'+('\n'.repeat(100000))+'y; interface Fields { token: string; }';
 assert.ok(typeFieldOffsets(text).has(text.indexOf('token:')));
 const trailing='interface Fields { token: string; }\nconst token="'+secret+'";';
 const fields=typeFieldOffsets(trailing);assert.ok(fields.has(trailing.indexOf('token:')));assert.equal(fields.has(trailing.lastIndexOf('token=')),false);
});
