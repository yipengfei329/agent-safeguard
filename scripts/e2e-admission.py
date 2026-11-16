"""Real-host prompt admission tests with synthetic data and a local model.

The temporary plugin emulates a downstream handler accepting, dropping or
throwing without starting a model turn. The shipped plugin is never modified.
"""
import http.server, json, os, pathlib, queue, shutil, subprocess, tempfile, threading
from importlib.util import spec_from_file_location, module_from_spec

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = spec_from_file_location('helpers', ROOT / 'scripts/e2e-recovery.py')
helpers = module_from_spec(spec); spec.loader.exec_module(helpers)
CASES = ['clean', 'handled', 'drop', 'exception', 'recovered-handled', 'queued-sdk']
SECRET = 'SYNTHETIC_ADMISSION_SECRET'

def run_case(name):
 with tempfile.TemporaryDirectory(prefix='safeguard-admission-') as tmp:
  base = pathlib.Path(tmp); home = base / 'home'; home.mkdir(); plugin = base / 'plugin'; plugin.mkdir()
  baseline = os.environ.get('SAFEGUARD_BASELINE_PLUGIN')
  source = pathlib.Path(baseline) if baseline else ROOT
  for folder in ['hooks', 'dist', '.claude-plugin']: shutil.copytree(source / folder, plugin / folder)
  cfg = json.loads((ROOT / 'config/tool-results.json').read_text()); cfg['schemaVersion'] = 2; cfg['policy']['recovery'] = 'next-safe-user-prompt'
  (plugin / 'local').mkdir(); (plugin / 'local/rules.json').write_text(json.dumps(cfg))
  fixture = base / 'fixture.txt'; fixture.write_text('password=' + SECRET)
  hook = plugin / 'hooks/register.js'; code = hook.read_text()
  begin = code.index("on('prompt.submit',"); end = code.index("on('prompt.section',", begin)
  handler = code[begin:end]
  assert handler.count('await next(e)') == 1
  expression = "(e.text==='LOCAL_SYNTHETIC' ? {text:e.text} : e.text==='DROP_SYNTHETIC' ? {drop:'SYNTHETIC_DOWNSTREAM_DROP'} : e.text==='THROW_SYNTHETIC' ? (()=>{throw Error('SYNTHETIC_DOWNSTREAM_ERROR')})() : await next(e))"
  hook.write_text(code[:begin] + handler.replace('await next(e)', expression) + code[end:])
  requests = []; entered = threading.Event(); release = threading.Event()
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self, *args): pass
   def do_POST(self):
    data = json.loads(self.rfile.read(int(self.headers['Content-Length']))); requests.append(data)
    if name == 'queued-sdk' and len(requests) == 1: entered.set(); release.wait(15)
    if name == 'recovered-handled' and len(requests) == 1:
     blocks = [{'type':'tool_use', 'id':'fixture', 'name':'Bash', 'input':{'command':'cat ' + str(fixture)}}]
    else: blocks = [{'type':'text', 'text':'SAFE_SYNTHETIC_ANSWER'}]
    msg = {'id':'msg_fixture','type':'message','role':'assistant','model':data['model'],'content':blocks,'stop_reason':'tool_use' if blocks[0]['type']=='tool_use' else 'end_turn','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
    body = helpers.events(msg); self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
  server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
  threading.Thread(target=server.serve_forever,daemon=True).start()
  env = {'PATH':os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'ANTHROPIC_API_KEY':'synthetic-local-only','ANTHROPIC_BASE_URL':f'http://127.0.0.1:{server.server_port}','DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
  args = [helpers.CLAUDE,'-p','--input-format','stream-json','--output-format','stream-json','--verbose','--plugin-dir',str(plugin),'--setting-sources','','--dangerously-skip-permissions','--tools','Bash','--model','claude-sonnet-4-6']
  proc = subprocess.Popen(args,cwd=base,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); replies = queue.Queue()
  def reader():
   for line in proc.stdout:
    try:
     row = json.loads(line)
     if row.get('type') == 'result': replies.put(row)
    except ValueError: pass
   replies.put({'type':'eof'})
  threading.Thread(target=reader,daemon=True).start(); threading.Thread(target=lambda:list(proc.stderr),daemon=True).start()
  def send(text): proc.stdin.write(json.dumps({'type':'user','message':{'role':'user','content':text}})+'\n'); proc.stdin.flush()
  def result():
   row = replies.get(timeout=30); assert row.get('type') != 'eof', 'host exited'; return row
  def status():
   before = len(requests); send('/agent-safeguard-status'); text = result().get('result','')
   assert len(requests) == before, 'status reached model: plugin was not loaded'
   return json.loads(text[text.index('{'):text.rindex('}')+1])
  try:
   initial = status(); assert initial['ready'] and not initial['blocked']
   if name == 'queued-sdk':
    send('FIRST synthetic question'); assert entered.wait(15)
    send('SECOND synthetic question'); release.set(); result(); result()
   elif name in ['clean','recovered-handled']:
    send('FIRST synthetic question'); result(); assert len(requests)==1
   if name in ['handled','recovered-handled']:
    count = len(requests); send('LOCAL_SYNTHETIC'); result(); assert len(requests)==count
   if name == 'drop':
    send('DROP_SYNTHETIC'); assert 'SYNTHETIC_DOWNSTREAM_DROP' in json.dumps(result()); assert not requests
   if name == 'exception':
    send('THROW_SYNTHETIC'); result(); assert not requests
    state=status(); assert state['blocked']
    if not baseline: assert not state['promptAdmission']['submitting']
    send('/agent-safeguard-check'); assert 'SAFEGUARD_HEALTH_OK' in json.dumps(result())
   before = len(requests); send('FOLLOWUP_SAFE: answer without tools.'); reply = result()
   reproduced = bool(baseline and name in ['handled','recovered-handled'])
   if reproduced:
    assert len(requests)==before and 'recovery.busy' in json.dumps(reply)
   else:
    assert len(requests)==before+1 and 'SAFE_SYNTHETIC_ANSWER' in json.dumps(reply)
    state=status(); assert not state['blocked']
    if not baseline: assert not state['promptAdmission']['submitting'] and not state['promptAdmission']['awaitingTurn']
   assert SECRET not in json.dumps(requests), 'held result reached model'
   proc.stdin.close(); proc.wait(timeout=15)
   return {'case':name,'passed':True,'modelRequests':len(requests),'baselineBusyReproduced':reproduced,'rawSecretInRequests':False}
  finally:
   release.set()
   if proc.poll() is None: proc.kill(); proc.wait()
   server.shutdown()

if __name__ == '__main__':
 if not helpers.CLAUDE: raise SystemExit('Claude Code is required')
 rows=[]
 for name in CASES:
  if os.environ.get('SAFEGUARD_CASE') and name != os.environ['SAFEGUARD_CASE']: continue
  try: row=run_case(name)
  except Exception as error: row={'case':name,'passed':False,'error':str(error)}
  rows.append(row); print(json.dumps(row),flush=True)
 (ROOT/'benchmarks/results').mkdir(exist_ok=True)
 (ROOT/'benchmarks/results/admission-e2e.json').write_text(json.dumps(rows,indent=2)+'\n')
 assert rows and all(row['passed'] for row in rows), 'admission cases failed'
