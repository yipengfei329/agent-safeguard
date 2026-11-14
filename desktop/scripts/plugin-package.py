#!/usr/bin/env python3
"""Create the bounded update asset; upload/publication is deliberately separate."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parents[2]
files=['.claude-plugin/plugin.json','hooks/register.js','hooks/hooks.json','dist/core.js','README.md','LICENSE']
package={'schema':1,'version':json.loads((root/files[0]).read_text())['version'],'files':{name:(root/name).read_text() for name in files}}
data=json.dumps(package,ensure_ascii=False,separators=(',',':')).encode()
assert len(data)<=4*1024*1024
out=root/'desktop/artifacts/agent-safeguard-plugin.json';out.parent.mkdir(exist_ok=True);out.write_bytes(data)
print(json.dumps({'asset':out.name,'version':package['version'],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}))
