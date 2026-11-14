#!/usr/bin/env python3
"""Repeatable macOS launch/RSS measurement; synthetic data; no user configuration."""
import argparse,json,pathlib,platform,selectors,statistics,subprocess,time
BASE=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--runs',type=int,default=20);p.add_argument('--seconds',type=int,default=30);args=p.parse_args()
exe=BASE/'artifacts/Agent Safeguard.app/Contents/MacOS/agent-safeguard-desktop'
if not exe.exists():raise SystemExit('Run package.py first')
def percentile(a,p):
    a=sorted(a);index=(len(a)-1)*p;lo=int(index);hi=min(lo+1,len(a)-1);return a[lo]+(a[hi]-a[lo])*(index-lo)
def launch(page='install'):
    start=time.perf_counter()
    proc=subprocess.Popen([str(exe),'--demo','--measure','--page',page],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
    try:
        end=time.monotonic()+20
        while time.monotonic()<end:
            if selector.select(.1):
                line=proc.stdout.readline()
                if not line:raise RuntimeError('app exited before ready marker')
                try:row=json.loads(line)
                except json.JSONDecodeError:continue
                if 'first_frame_callback_ms' in row:
                    return proc,{'spawn_to_callback_ms':round((time.perf_counter()-start)*1000,3),**row}
        raise RuntimeError('ready timeout')
    except Exception:
        proc.kill();proc.wait();raise
    finally:selector.close()
def stop(proc):
    proc.terminate()
    try:proc.wait(timeout=5)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
def rss_tree(pid):
    # Keep only numeric process metadata, never capture command lines or paths.
    lines=subprocess.check_output(['ps','-axo','pid=,ppid=,rss=,%cpu='],text=True).splitlines()
    entries={}
    for line in lines:
        cols=line.split()
        if len(cols)==4:entries[int(cols[0])]=(int(cols[1]),int(cols[2]),float(cols[3]))
    selected={pid}
    while True:
        expanded=selected|{p for p,(parent,_,_) in entries.items() if parent in selected}
        if expanded==selected:break
        selected=expanded
    rows=[entries[p] for p in selected if p in entries]
    return {'rss_mib':round(sum(r[1] for r in rows)/1024,3),'cpu_percent_ps':round(sum(r[2] for r in rows),3),'processes':len(rows)}
launches=[]
for i in range(args.runs):
    proc,row=launch();stop(proc);launches.append(row);time.sleep(.3)
mem={}
for page in ['install','status','rules']:
    proc,_=launch(page)
    try:
        time.sleep(3)
        samples=[]
        for i in range(args.seconds):samples.append(rss_tree(proc.pid));time.sleep(1)
        mem[page]={'samples':samples,'rss_mib_median':statistics.median(s['rss_mib'] for s in samples),'rss_mib_max':max(s['rss_mib'] for s in samples),'cpu_percent_ps_median':statistics.median(s['cpu_percent_ps'] for s in samples)}
    finally:stop(proc)
values=[r['spawn_to_callback_ms'] for r in launches]
report={'platform':{'os':'macOS','version':platform.mac_ver()[0],'architecture':platform.machine()},'mode':'Release app executable; synthetic demo; no harness probe; local process spawn, not Finder/Gatekeeper','startup_marker':'callback scheduled during initial render; subsequent frame callback, not measured display scanout or input latency','cache':'first observed launch reported separately; OS/font/shader caches not flushed, NOT cold boot','launches':launches,'startup_ms':{'first_observed':values[0],'p50':percentile(values,.5),'p95':percentile(values,.95),'min':min(values),'max':max(values)},'memory':mem,'memory_method':'ps RSS summed over app and descendants; shared pages may double-count; WindowServer/GPU allocations excluded; rule validation uses an embedded JS runtime','sample_seconds_per_page':args.seconds}
(BASE/'artifacts/measurements.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'startup_ms':report['startup_ms'],'rss_mib_median':{p:r['rss_mib_median'] for p,r in mem.items()}},indent=2))
