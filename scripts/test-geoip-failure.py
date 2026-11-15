#!/usr/bin/env python3
"""Isolated Mods test of a loadable engine with damaged embedded GeoIP data."""
import json,pathlib,shutil,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
snapshot=json.loads((root/'data/geoip-country.js').read_text().split('export default ',1)[1].rstrip(';\n'))
with tempfile.TemporaryDirectory(prefix='safeguard-geo-failure-') as tmp:
    plugin=pathlib.Path(tmp)
    for folder in ['.claude-plugin','hooks','dist']:shutil.copytree(root/folder,plugin/folder)
    core=plugin/'dist/core.js';text=core.read_text();needle='"checksum": '+str(snapshot['checksum'])
    assert text.count(needle)==1
    core.write_text(text.replace(needle,'"checksum": 0'))
    cfg=json.loads((root/'config/rules.example.json').read_text());cfg['rules'][0]['enabled']=False
    (plugin/'tests').mkdir()
    (plugin/'tests/failure.test.ts').write_text('''
import {test,expect} from 'claude-code/testing';
test('damaged database blocks initialization and prevents tool execution',async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));
 let executions=0;on('tool.call',()=>{executions++;return {result:'BUILD_OK'};});
 const prompt=await $.prompt.submit({text:'Build the project'});expect(prompt.drop).toContain('initialization.failed');
 const result=await $.tool.call({tool:'Bash',command:'fixture'});expect(result.deny).toBe('SAFEGUARD_BLOCKED');expect(executions).toBe(0);
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.ready).toBe(false);expect(status.lastRule).toBe('initialization.failed');
});
test('explicitly disabled country rule needs no database; credentials still checked',async($,on)=>{
 on('fs.exists',($,e)=>({value:!e.path.endsWith('desktop.json')}));
 on('fs.read',()=>({value:CONFIG}));on('command.register',()=>({value:undefined}));on('prompt.submit',($,e)=>({text:e.text}));
 expect((await $.prompt.submit({text:'Build the project'})).text).toBe('Build the project');
 expect((await $.prompt.submit({text:'password=SYNTHETIC_SECRET'})).drop).toContain('security.credentials');
});
'''.replace('CONFIG',json.dumps(json.dumps(cfg))))
    subprocess.run(['claude','plugin','test',str(plugin)],cwd=plugin,check=True)
