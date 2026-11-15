#!/usr/bin/env python3
"""Build a local macOS prototype. No signing identity or publication required."""
import argparse, json, pathlib, platform, plistlib, shutil, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[2]
DESKTOP=ROOT/'desktop'
OUT=DESKTOP/'artifacts'
p=argparse.ArgumentParser();p.add_argument('--skip-build',action='store_true');args=p.parse_args()
cargo=shutil.which('cargo') or str(pathlib.Path.home()/'.cargo/bin/cargo')
if not args.skip_build:
    subprocess.run(['npm','run','build'],cwd=ROOT,check=True)
    subprocess.run([cargo,'build','--release','--locked'],cwd=DESKTOP,check=True)
if platform.system()!='Darwin' or platform.machine()!='arm64':raise SystemExit('This prototype packager currently targets macOS arm64 only.')
OUT.mkdir(exist_ok=True)
app=OUT/'Agent Safeguard.app'
if app.exists():shutil.rmtree(app)
mac=app/'Contents/MacOS';res=app/'Contents/Resources'
mac.mkdir(parents=True);res.mkdir()
shutil.copy2(DESKTOP/'target/release/agent-safeguard-desktop',mac/'agent-safeguard-desktop')
with (app/'Contents/Info.plist').open('wb') as f:
    plistlib.dump({'CFBundleName':'Agent Safeguard','CFBundleDisplayName':'Agent Safeguard','CFBundleIdentifier':'dev.agent-safeguard.prototype','CFBundleExecutable':'agent-safeguard-desktop','CFBundlePackageType':'APPL','CFBundleShortVersionString':'0.2.0','CFBundleVersion':'2','NSHighResolutionCapable':True},f)
shutil.copy2(ROOT/'LICENSE',res/'LICENSE')
# Ship dependency notices/licenses, without local paths or account identifiers.
metadata=json.loads(subprocess.check_output([cargo,'metadata','--format-version','1','--locked'],cwd=DESKTOP))
notices=[(ROOT/'data/NOTICE.md').read_text()]
for package in sorted(metadata['packages'],key=lambda p:p['name']):
    if package['name']=='agent-safeguard-desktop':continue
    notices.append(f"\n{package['name']} {package['version']} | {package.get('license') or 'see package license'}\n")
    folder=pathlib.Path(package['manifest_path']).parent
    license_files=sorted(set(folder.glob('LICENSE*'))|set(folder.glob('COPYING*')))
    for license_file in license_files:
        if license_file.is_file():notices.append(license_file.read_text(errors='replace'))
(res/'THIRD_PARTY_LICENSES.txt').write_text('\n'.join(notices))
subprocess.run(['codesign','--force','--deep','--sign','-',str(app)],check=True)
subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True)
zip_path=OUT/'Agent-Safeguard-macos-arm64.zip'
if zip_path.exists():zip_path.unlink()
subprocess.run(['ditto','-c','-k','--keepParent',str(app),str(zip_path)],check=True)
dmg_path=OUT/'Agent-Safeguard-macos-arm64.dmg'
stage=OUT/'dmg-stage'
if stage.exists():shutil.rmtree(stage)
stage.mkdir();shutil.copytree(app,stage/app.name);(stage/'Applications').symlink_to('/Applications')
if dmg_path.exists():dmg_path.unlink()
subprocess.run(['hdiutil','create','-volname','Agent Safeguard','-srcfolder',str(stage),'-ov','-format','UDZO',str(dmg_path)],check=True,stdout=subprocess.DEVNULL)
shutil.rmtree(stage)
sizes={'executable_bytes':(mac/'agent-safeguard-desktop').stat().st_size,'app_logical_bytes':sum(f.stat().st_size for f in app.rglob('*') if f.is_file()),'zip_bytes':zip_path.stat().st_size,'dmg_bytes':dmg_path.stat().st_size,'signing':'ad-hoc; not notarized','node_bundled':False,'external_node_required_for':None,'embedded_validator':'QuickJS; same bundled detection engine'}
(OUT/'package-sizes.json').write_text(json.dumps(sizes,indent=2)+'\n')
print(json.dumps(sizes,indent=2))
