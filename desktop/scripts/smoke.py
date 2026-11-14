#!/usr/bin/env python3
"""Isolated install/update tests. Never modifies the user's Claude installation."""
import json,os,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
EXE=ROOT/'desktop/target/release/agent-safeguard-desktop'
def invoke(base,env,action,ok=True):
    p=subprocess.run([str(EXE),'--data-dir',str(base/'data'),'--backend',action],env=env,cwd=base,capture_output=True,text=True,timeout=75)
    result=json.loads(p.stdout)
    assert result['ok']==ok,(action,result)
    assert 'SYNTHETIC_SECRET' not in p.stdout+p.stderr
    return result
with tempfile.TemporaryDirectory(prefix='safeguard-desktop-test-') as tmp:
    base=pathlib.Path(tmp);commands=base/'bin';commands.mkdir();home=base/'home';home.mkdir()
    fake=commands/'claude'
    fake.write_text("""#!/usr/bin/env python3
import os,sys,json
if os.environ.get('FIXTURE_FAIL'): print('SYNTHETIC_SECRET',file=sys.stderr);sys.exit(1)
if '--version' in sys.argv: print('2.1.325 (Claude Code)')
elif 'list' in sys.argv: print(json.dumps([{'id':'agent-safeguard@agent-safeguard-local','version':'0.1.7','enabled':True,'scope':'user'}]))
else: print(json.dumps({'ok':True}))
""");fake.chmod(0o755)
    env={**os.environ,'PATH':str(commands)+os.pathsep+os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config')}
    invoke(base,env,'install')
    plugin=base/'data/marketplace/plugins/agent-safeguard'
    rules=plugin/'local/rules.json';rules.write_text('{"fixture":"SYNTHETIC_PRIVATE_RULE"}')
    invoke(base,env,'update');assert rules.read_text()=='{"fixture":"SYNTHETIC_PRIVATE_RULE"}'
    hook=plugin/'hooks/register.js';hook.write_text('fixture previous runtime')
    result=invoke(base,{**env,'FIXTURE_FAIL':'1'},'update',False)
    assert result['code']=='COMMAND_FAILED';assert hook.read_text()=='fixture previous runtime'
    assert rules.read_text()=='{"fixture":"SYNTHETIC_PRIVATE_RULE"}'
    manifest=plugin/'.claude-plugin/plugin.json';obj=json.loads(manifest.read_text());obj['version']='99.0.0';manifest.write_text(json.dumps(obj))
    assert invoke(base,env,'update',False)['code']=='BUNDLED_VERSION_OLDER'
    assert hook.read_text()=='fixture previous runtime'
    print('PASS: isolated mock install, rule preservation, failed update restore, sanitized errors, downgrade refusal')
# Actual CLI contract, local marketplace, isolated HOME/config/work directory.
claude=shutil.which('claude')
if not claude:raise SystemExit('Claude unavailable; actual CLI smoke not run')
with tempfile.TemporaryDirectory(prefix='safeguard-desktop-cli-') as tmp:
    base=pathlib.Path(tmp);home=base/'home';home.mkdir()
    env={'PATH':str(pathlib.Path(claude).parent)+os.pathsep+os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
    invoke(base,env,'install')
    def current():
        p=subprocess.run([claude,'plugin','list','--json'],env=env,cwd=base,capture_output=True,text=True,timeout=20)
        assert p.returncode==0
        return next(row for row in json.loads(p.stdout) if row['id']=='agent-safeguard@agent-safeguard-local' and row['scope']=='user')
    assert current()['version']==json.loads((ROOT/'.claude-plugin/plugin.json').read_text())['version']
    invoke(base,env,'disable');assert current()['enabled'] is False
    invoke(base,env,'enable');assert current()['enabled'] is True
    invoke(base,env,'update');assert current()['version']==json.loads((ROOT/'.claude-plugin/plugin.json').read_text())['version']
    invoke(base,env,'uninstall');assert (base/'data/marketplace/plugins/agent-safeguard/local/rules.json').exists()
    print('PASS: actual Claude CLI isolated install, list, disable, enable, update')
