#!/usr/bin/env python3
"""Parity check: the same configs through Node and the embedded validator."""
import copy,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[2]
exe=root/'desktop/target/release/agent-safeguard-desktop'
base=json.loads((root/'config/tool-results.json').read_text())
cases=[('valid-template',base)]
def add(name,change):
 cfg=copy.deepcopy(base);change(cfg);cases.append((name,cfg))
add('bad-cidr',lambda c:c['rules'][0]['detector'].update(excludeCidrs=['invalid']))
add('duplicate-id',lambda c:c['rules'].append(copy.deepcopy(c['rules'][0])))
add('bad-source',lambda c:c['rules'][0].update(sources=['unknown']))
add('tool-scope-on-prompt',lambda c:c['rules'][0].update(tools=['Bash']))
add('observe-preserved',lambda c:c['rules'][0].update(action='observe'))
add('unicode-values',lambda c:c['rules'][4]['detector'].update(values=['虚构标记😀','\ud800']))
add('rule-budget',lambda c:c['limits'].update(maxRules=1))
add('invalid-domain',lambda c:c['rules'][5]['detector'].update(suffixes=['invalid']))
add('extra-field',lambda c:c.update(unknown=True))
node="import {compile} from './dist/core.js';import {readFileSync} from 'node:fs';try{compile(JSON.parse(readFileSync(0,'utf8')))}catch{process.exitCode=2}"
for name,cfg in cases:
 text=json.dumps(cfg)
 reference=subprocess.run(['node','--input-type=module','-e',node],cwd=root,input=text,text=True,capture_output=True)
 native=subprocess.run([str(exe),'--backend','validate'],cwd=root,input=text,text=True,capture_output=True)
 assert (reference.returncode==0)==json.loads(native.stdout)['ok'],name
print(f'PASS: {len(cases)} validation cases agree with the original Node engine')
