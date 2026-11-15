"""Synthetic local Messages API recorder; no account credentials are inherited."""
import http.server,threading,json,tempfile,pathlib,subprocess,os,shutil,base64
ROOT=pathlib.Path(__file__).resolve().parent.parent
CLAUDE=os.environ.get('SAFEGUARD_CLAUDE_BIN') or shutil.which('claude')
report=[]
installed_mode=os.environ.get("SAFEGUARD_TEST_INSTALLED")=="1"
cases=[('control-sensitive','203.0.113.17',False),('guard-sensitive','203.0.113.17',True),('guard-clean','BUILD_OK',True),('guard-stderr','203.0.113.17',True),('strict-context-compatibility-block','BUILD_OK',True)]
for fixture in json.loads((ROOT/'fixtures/replays.json').read_text()):
 if fixture['block'] and fixture['name']!='未知图片':cases.append(('replay-'+fixture['name'],json.dumps(fixture['value'],ensure_ascii=False),True))
if installed_mode:cases=cases[:4]
cases += [('guard-user-path','/Users/example/Code/project\n/home/example/src/project',True),('guard-user-path-sensitive','/Users/example/Code/project 203.0.113.17',True)]
cases += [('guard-email','Author: Example <person@example.invalid>\nCo-authored-by: Example Bot <bot@example.invalid>',True),('guard-email-sensitive','person@example.invalid password=SYNTHETIC_SECRET',True)]
cases += [('guard-local-network','127.0.0.1 10.23.45.67 172.20.0.5 192.168.50.1 100.64.0.1 198.18.1.7 0.0.0.0 ::1 fd00::1 fe80::1%en0 ::ffff:192.168.50.1',True),('guard-local-network-public','127.0.0.1 192.168.50.1 ::ffff:203.0.113.17',True),('guard-local-network-secret','127.0.0.1 password=SYNTHETIC_SECRET',True)]
cases += [('guard-type-declaration','public var secret: Bool = false\nlet password: String\nconst token: string;',True),('guard-typed-password','let password: String = "SYNTHETIC_PASSWORD"',True),('guard-declaration-token','public var secret: Bool = false\nconst token: string = "SYNTHETIC_TOKEN"',True),('guard-data-type-word','{"secret":"Bool"}',True)]
cases += [
 ('guard-grep-command-label', 'src/fake.go:21:case "ask", "ask-secret":\nsrc/fake.go:26:item := Question{Secret: cmd == "ask-secret"}', True),
 ('guard-code-references', 'const token = config.token;\nself.password = os.environ.get("PASSWORD")\nopts := Options{Token: config.Token, Secret: false}', True),
 ('guard-code-adjacent-secret', 'const token = config.token; password=SYNTHETIC_PASSWORD', True),
 ('guard-multiline-secret', 'password:\n  SYNTHETIC_PASSWORD', True),
 ('guard-data-code-word', '{"token":"config.token"}', True),
 ('guard-credential-stderr', 'token=SYNTHETIC_TOKEN', True),
]
cases += [('guard-image','SYNTHETIC_IMAGE',True),('guard-css','9::root{--live:#5f6b85}\n12:.map::before{color:red}',True),('guard-css-public','9::root{--live:#5f6b85}\n2001:db8::7',True)]
cases += [
 ('guard-identity-code','interface Config { hostname: string; device_id: string; }\nconst hostname = os.hostname();\nconst serialNumber = device.serialNumber;',True),
 ('guard-authorization-reference','Authorization: Bearer ${SESSION_TOKEN}',True),
 ('guard-punctuation-ip','connected to 203.0.113.17.',True),
 ('guard-punctuation-ipv6','peer 2001:db8::7.',True),
 ('guard-device-value','serialNumber: SYNTHETIC12345',True),
 ('guard-host-value','hostname: ExampleMac',True),
 ('guard-array-token','{"token":["SYNTHETIC_TOKEN"]}',True),
 ('guard-number-password','{"password":123456}',True),
]
# Public database probes, never contacted; no user IPs. Historical replay
# fixtures keep the explicit any-address profile in isolated plugin copies.
cases=[(n,v if n.startswith('replay-') else v.replace('203.0.113.17','1.0.1.7').replace('2001:db8::7','2400:3200::7'),g) for n,v,g in cases]
cases += [('guard-geo-other','8.8.8.8',True),('guard-geo-unknown','203.0.113.17 2001:db8::7',True),('guard-geo-mixed','8.8.8.8 1.0.1.7',True)]
cases += [('guard-rust-types','pub api_key: String,\npub(crate) token: Option<std::sync::Arc<SecretString>>,',True),('guard-test-token','App/Push.swift:23: if token == nil, arguments.contains("-SyntheticTestApprove") { token = "simulator" }',True),('guard-rust-secret','pub api_key: String,\nlet token: Option<String> = Some("rQ7!mL2_zA9#vC4-pF8@tN6".into());',True)]
simulator={'deviceId':'11111111-2222-4333-8444-555555555555','platform':'iOS Simulator','deviceName':'Synthetic E2E'}
simlog='UI tests failed:\n'+'\n'.join(f'{i+3}-{line}' for i,line in enumerate(json.dumps({'devices':[simulator]},indent=2).splitlines()))
cases += [('guard-simulator-json',json.dumps({'devices':[simulator]}),True),('guard-simulator-grep',simlog,True),('guard-simulator-real',json.dumps({**simulator,'platform':'iOS'}),True),('guard-simulator-mixed',json.dumps({'devices':[simulator,{'deviceId':simulator['deviceId']}]}),True),('guard-simulator-secret',simlog+'\npassword=SYNTHETIC_PASSWORD',True),('guard-simulator-serial',json.dumps({**simulator,'serialNumber':'SYNTHETIC12345'}),True)]
cases += [('guard-swift-expression','let r = try await call("synthetic/set", ["api_key": .string(key)])',True),('guard-unknown-expression','["api_key": .unknown_Ab7_Kd3_Xp9[factory](reference)!]',True),('guard-swift-literal','["api_key": .string("rQ7!mL2_zA9#vC4-pF8@tN6")]',True)]
precision_code='interface Options { token: "custom-type-discriminant"; }\nconst password = "Please enter your password";\nconst secret = "AWS_SECRET_ACCESS_KEY";'
cases += [
 ('guard-precision-code',precision_code,True),
 ('guard-precision-label','const token = "application/json";\nconst token = "/var/run/secrets/service-account/token";',True),
 ('guard-precision-adjacent',precision_code+'\napi_key=rQ7!mL2_zA9#vC4-pF8@tN6',True),
 ('guard-precision-stderr',precision_code+'\napi_key=rQ7!mL2_zA9#vC4-pF8@tN6',True),
 ('guard-precision-comment','interface Options { /* password=rQ7!mL2_zA9#vC4-pF8@tN6 */ value: string; }',True),
 ('guard-precision-initializer','let token: "custom-type-discriminant" = "rQ7!mL2_zA9#vC4-pF8@tN6";',True),
 ('guard-precision-regex','function render() { const pattern = /interface Options {/; const x = { token: "rQ7!mL2_zA9#vC4-pF8@tN6" }; }',True),
]
boundary_clean={'guard-boundary-empty','guard-boundary-metadata','guard-boundary-reference','guard-shape-reference','guard-shape-reference-error','guard-shared-calls','guard-shared-error','guard-shared-reference','guard-shared-ui'}
cases += [
 ('guard-boundary-empty','PASSWORD= HOST=demo-service',True),
 ('guard-boundary-metadata','token_count=1234567890\naccess_token_expires_at="2026-11-15T12:34:56Z"',True),
 ('guard-boundary-reference','DB_PASSWORD="${DB_PASSWORD}"',True),
 ('guard-boundary-prefixed','DB_PASSWORD="vD8!qZ3_nB7#sJ5-pR2@wK9"',True),
 ('guard-boundary-template','DB_PASSWORD="vD8!qZ3_nB7#sJ5-pR2@wK9${SUFFIX}"',True),
 ('guard-boundary-redis','redis://:xyz@cache.example.invalid',True),
 ('guard-boundary-adjacent','PASSWORD= SERVICE_API_TOKEN=vD8!qZ3_nB7#sJ5-pR2@wK9',True),
 ('guard-boundary-stderr','SERVICE_API_TOKEN=vD8!qZ3_nB7#sJ5-pR2@wK9',True),
 ('guard-shape-reference','["Authorization": "<binding:credential>"]',True),
 ('guard-shape-reference-error','["Authorization": "[source:session]"]',True),
 ('guard-shape-material','["Authorization": "<binding:mT8!rV3_zQ7#bK5-pN2@xD9>"]',True),
 ('guard-shape-adjacent','["Authorization": "<binding:credential>"]\nDB_PASSWORD=mT8!rV3_zQ7#bK5-pN2@xD9',True),
 ('guard-shared-calls','    device_id = identity_service.resolve_identity(\n        payload.device_id,\n    )\n    hostname = names.resolve_host(request)',True),
 ('guard-shared-error','device_id = identity_service.resolve_identity(',True),
 ('guard-shared-reference','device_id = payload.device_id\nhostname = names.current_host',True),
 ('guard-shared-ui','{"device_id":"Enter the device identifier","hostname":"<binding:host>"}',True),
 ('guard-shared-device','device_id = identity_service.resolve_identity(\ndevice_id="SYNTHETIC456789"',True),
 ('guard-shared-host','hostname = names.resolve_host(request)\nhostname="SyntheticHost"',True),
 ('guard-shared-stderr','device_id = identity_service.resolve_identity(\nserialNumber="SYNTHETIC456789"',True),
 ('guard-shared-secret','device_id = identity_service.resolve_identity(\npassword="pM8!sQ3_vL7#rD5-tN2@xK9"',True),
]
for name,output,guard in cases:
 with tempfile.TemporaryDirectory(prefix='safeguard-e2e-') as tmp:
  base=pathlib.Path(tmp);requests=[]
  (base/'fixture.png').write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZ1sAAAAASUVORK5CYII='))
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    data=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(data)
    has_result=any(isinstance(m.get('content'),list) and any(b.get('type')=='tool_result' for b in m['content']) for m in data.get('messages',[]))
    blocks=[{'type':'text','text':'done'}] if has_result else [{'type':'tool_use','id':'tool_fixture','name':'Bash','input':{'command':"printf %s "+base64.b64encode(output.encode()).decode()+" | base64 --decode"+(" >&2; exit 1" if name in ["guard-stderr","guard-credential-stderr","guard-precision-stderr","guard-boundary-stderr","guard-shape-reference-error","guard-shared-error","guard-shared-stderr"] else ""),'description':'Synthetic fixture'}}]
    if name=='guard-image' and not has_result:blocks=[{'type':'tool_use','id':'tool_fixture','name':'Read','input':{'file_path':str(base/'fixture.png')}}]
    message={'id':'msg_fixture','type':'message','role':'assistant','model':data.get('model','test'),'content':blocks,'stop_reason':'end_turn' if has_result else 'tool_use','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
    if data.get('stream'):
     events=[('message_start',{'type':'message_start','message':{**message,'content':[],'stop_reason':None}})]
     for i,b in enumerate(blocks):
      start={**b};start['text']='' if b['type']=='text' else start.get('text','');
      if b['type']=='tool_use':start.pop('text',None);start['input']={}
      events.append(('content_block_start',{'type':'content_block_start','index':i,'content_block':start}))
      delta={'type':'text_delta','text':b['text']} if b['type']=='text' else {'type':'input_json_delta','partial_json':json.dumps(b['input'])}
      events.extend([('content_block_delta',{'type':'content_block_delta','index':i,'delta':delta}),('content_block_stop',{'type':'content_block_stop','index':i})])
     events.extend([('message_delta',{'type':'message_delta','delta':{'stop_reason':message['stop_reason'],'stop_sequence':None},'usage':{'output_tokens':10}}),('message_stop',{'type':'message_stop'})])
     body=''.join('event: '+event+'\ndata: '+json.dumps(d)+'\n\n' for event,d in events).encode();ctype='text/event-stream'
    else:body=json.dumps(message).encode();ctype='application/json'
    self.send_response(200);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  home=base/'home';home.mkdir();work=base/'work';work.mkdir()
  env={'PATH':os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'ANTHROPIC_API_KEY':'synthetic-local-only','ANTHROPIC_BASE_URL':f'http://127.0.0.1:{server.server_port}','DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
  prompt='项目根目录：/Users/example/Code/project 分支 claude/fixture-branch 检查工作进展' if name.startswith('guard-user-path') else 'Run the fixture command.'
  if name.startswith('guard-local-network'):prompt='Check local service 127.0.0.1 and 192.168.50.1'
  if name=='guard-type-declaration':prompt='Explain public var secret: Bool = false'
  if name.startswith('guard-email'):prompt='Find commits by person@example.invalid'
  args=[CLAUDE,'-p',prompt,'--no-session-persistence','--setting-sources','','--dangerously-skip-permissions','--tools','Bash,Read','--model','claude-sonnet-4-6','--max-turns','3']
  if guard and installed_mode:
   userroot=pathlib.Path.home()/'.claude';testroot=home/'config';(testroot/'plugins').mkdir(parents=True)
   settings=json.loads((userroot/'settings.json').read_text())
   settings={k:settings[k] for k in ['enabledPlugins','extraKnownMarketplaces'] if k in settings}
   settings['enabledPlugins']={'agent-safeguard@agent-safeguard-local':True}
   if 'extraKnownMarketplaces' in settings:settings['extraKnownMarketplaces']={k:v for k,v in settings['extraKnownMarketplaces'].items() if k=='agent-safeguard-local'}
   (testroot/'settings.json').write_text(json.dumps(settings))
   registry=json.loads((userroot/'plugins/installed_plugins.json').read_text());registry['plugins']={'agent-safeguard@agent-safeguard-local':registry['plugins']['agent-safeguard@agent-safeguard-local']}
   (testroot/'plugins/installed_plugins.json').write_text(json.dumps(registry))
   markets=json.loads((userroot/'plugins/known_marketplaces.json').read_text());(testroot/'plugins/known_marketplaces.json').write_text(json.dumps({'agent-safeguard-local':markets['agent-safeguard-local']}))
   args[args.index('--setting-sources')+1]='user'
  elif guard:
   plugin=base/'plugin';plugin.mkdir()
   for directory in ['hooks','dist','.claude-plugin']:shutil.copytree(ROOT/directory,plugin/directory)
   (plugin/'local').mkdir();cfg=json.loads((ROOT/'config/rules.example.json').read_text())
   if name.startswith('replay-'):
    cfg['rules'][0]['detector']['mode']='any';cfg['rules'][0]['detector'].pop('country');cfg['rules'][0]['detector'].pop('onUnknown')
   # Isolate tool-result interception; context policy tested separately with native harness.
   if name!='strict-context-compatibility-block':
    for rule in cfg['rules']:rule['sources']=[s for s in rule['sources'] if s.startswith('tool.')]
   (plugin/'local/rules.json').write_text(json.dumps(cfg));args+=['--plugin-dir',str(plugin)]
  try:
   p=subprocess.run(args,env=env,cwd=work,capture_output=True,text=True,timeout=40)
   leaked=any('1.0.1.7' in json.dumps(m.get('content')) for req in requests for m in req.get('messages',[]) if m.get('role')=='user')
   report.append({'case':name,'requests':len(requests),'sensitive_in_user_payload':leaked,'exit':p.returncode,'stdout_tail':p.stdout[-300:],'stderr_tail':p.stderr[-300:],'image_submitted':any('image/png' in json.dumps(m.get('content')) for req in requests for m in req.get('messages',[]) if m.get('role')=='user')})
  except subprocess.TimeoutExpired:report.append({'case':name,'requests':len(requests),'timeout':True})
  finally:server.shutdown()
print(json.dumps(report,indent=2))
(ROOT/'benchmarks/results').mkdir(exist_ok=True)
(ROOT/('benchmarks/results/installed-e2e.json' if installed_mode else 'benchmarks/results/e2e.json')).write_text(json.dumps(report,indent=2))
assert report[0].get('sensitive_in_user_payload'), 'Control must demonstrate actual sensitive tool-result submission'
assert report[1].get('requests')==1 and not report[1].get('sensitive_in_user_payload'), 'Guard must stop follow-up request'
assert report[2].get('requests',0)>=2 and report[2].get('exit')==0, 'Clean path must continue'

for row in report[3:]:
 # Host-generated context varies by CLI build. The unmodified 0.1.6 baseline
 # also completes this clean probe on 2.1.325; native tests inject explicit
 # sensitive context to verify gating deterministically. Record compatibility,
 # never treat this probe as evidence of blanket context coverage.
 if row['case']=='strict-context-compatibility-block':
  assert row.get('requests') in [1,2] and row.get('exit')==0, row['case']
  continue
 if row['case'] in boundary_clean:
  assert row.get('requests')==2 and row.get('exit')==0, row['case']
  continue
 assert row.get('requests')==(2 if row['case'] in ['guard-precision-code','guard-precision-label','guard-swift-expression','guard-unknown-expression','guard-simulator-json','guard-simulator-grep','guard-rust-types','guard-test-token','guard-data-type-word','guard-data-code-word','guard-number-password','guard-geo-other','guard-geo-unknown','guard-user-path','guard-email','guard-local-network','guard-type-declaration','guard-grep-command-label','guard-code-references','guard-image','guard-css','guard-identity-code','guard-authorization-reference'] else 1) and row.get('exit')==0, row['case']

assert next(r for r in report if r['case']=='guard-image').get('image_submitted'), 'Image must actually reach the follow-up model request'
