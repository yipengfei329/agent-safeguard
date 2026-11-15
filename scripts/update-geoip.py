#!/usr/bin/env python3
"""Offline conversion of a verified DB-IP CSV. Does not run inside the guard.

Download the monthly gzip from https://db-ip.com/db/download/ip-to-country-lite
over verified HTTPS, verify the publisher digest, then pass the decompressed
CSV SHA-256 explicitly. The current snapshot is replaced only after validation.
"""
import argparse,base64,csv,gzip,hashlib,io,ipaddress,json,pathlib,re,struct,tempfile,os

def convert(raw,month,expected):
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])',month) or hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('SOURCE_VERIFICATION_FAILED')
    groups={4:[],6:[]};records=0
    for row in csv.reader(io.StringIO(raw.decode('utf-8'))):
        if len(row)!=3:raise ValueError('INVALID_CSV')
        first,last,country=row;a,b=ipaddress.ip_address(first),ipaddress.ip_address(last)
        if a.version!=b.version or int(a)>int(b) or not re.fullmatch('[A-Z]{2}',country):raise ValueError('INVALID_RANGE')
        state=1 if country=='CN' else 0 if country in ('ZZ','XX') else 2
        table=groups[a.version];lo,hi=int(a),int(b);records+=1
        if table and table[-1][1]>=lo:raise ValueError('OVERLAPPING_RANGE')
        if table and table[-1][1]+1==lo and table[-1][2]==state:table[-1][1]=hi
        else:table.append([lo,hi,state])
    if records<100000 or any(not any(row[2]==1 for row in t) or not any(row[2]==2 for row in t) for t in groups.values()):
        raise ValueError('INCOMPLETE_DATABASE')
    words=[]
    for family,table in groups.items():
        for lo,hi,state in table:
            for address in (lo,hi):
                words.extend((address>>shift)&0xffffffff for shift in range(0 if family==4 else 96,-1,-32))
            words.append(state)
    payload=struct.pack('<'+'I'*len(words),*words);checksum=2166136261
    for byte in payload:checksum=((checksum^byte)*16777619)&0xffffffff
    if len(payload)>675000:raise ValueError('DATABASE_SIZE_LIMIT')
    return dict(schema=1,format='cn-other-unknown-u32le-v1',month=month,sourceSha256=expected,
        counts=[len(groups[4]),len(groups[6])],checksum=checksum,payload=base64.b64encode(payload).decode())

def main():
    p=argparse.ArgumentParser();p.add_argument('--csv-gz',required=True,type=pathlib.Path);p.add_argument('--month',required=True);p.add_argument('--sha256',required=True)
    args=p.parse_args();raw=gzip.decompress(args.csv_gz.read_bytes());data=convert(raw,args.month,args.sha256)
    root=pathlib.Path(__file__).resolve().parents[1];destination=root/'data/geoip-country.js';destination.parent.mkdir(exist_ok=True)
    content='// Derived from DB-IP Country Lite. CC BY 4.0; see data/NOTICE.md.\nexport default '+json.dumps(data,separators=(',',':'))+';\n'
    # Validate with the production portable reader before publishing. Node test
    # import needs an existing snapshot on the very first bootstrap only.
    import subprocess
    check="import {createGeoIP} from './src/geoip.js';import {readFileSync} from 'node:fs';createGeoIP(JSON.parse(readFileSync(0,'utf8')));"
    subprocess.run(['node','--input-type=module','-e',check],cwd=root,input=json.dumps(data),text=True,check=True)
    with tempfile.NamedTemporaryFile(mode='w',dir=destination.parent,delete=False) as f:
        try:f.write(content);f.flush();os.fsync(f.fileno());os.replace(f.name,destination)
        finally:
            if os.path.exists(f.name):os.unlink(f.name)
    print(json.dumps({k:v for k,v in data.items() if k!='payload'}))
if __name__=='__main__':main()
