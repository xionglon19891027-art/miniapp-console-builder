"""Exact-file release packaging. Dry-run by default; no source modification."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile
from checks import CheckError, safe_path, forbidden, has_secret

def run(a):
    root=Path(a.root).resolve(strict=True)
    if not root.is_dir(): raise CheckError('INVALID_ROOT')
    out=Path(a.output).absolute()
    if out.is_symlink() or out.resolve().is_relative_to(root): raise CheckError('OUTPUT_MUST_BE_EXTERNAL')
    side=Path(str(out)+'.manifest.json')
    if out.exists() or side.exists() or side.is_symlink(): raise CheckError('OUTPUT_EXISTS')
    m=json.loads(Path(a.manifest).read_text())
    if m.get('schemaVersion')!=1 or m.get('target') not in {'backend','cloud-function'}: raise CheckError('INVALID_MANIFEST')
    files=m.get('files'); required=m.get('required',[])
    if not isinstance(files,list) or not files or not all(isinstance(x,str) for x in files): raise CheckError('INVALID_FILES')
    if not isinstance(required,list) or not all(isinstance(x,str) for x in required): raise CheckError('INVALID_REQUIRED')
    if len(files)!=len(set(files)): raise CheckError('DUPLICATE_FILE')
    if not set(required).issubset(files): raise CheckError('REQUIRED_MISSING')
    payload={}
    for name in files:
        path=safe_path(root,name)
        if forbidden(name,m['target']): raise CheckError('FORBIDDEN_FILE: '+name)
        if not path.is_file(): raise CheckError('MISSING_FILE: '+name)
        data=path.read_bytes()
        if has_secret(data): raise CheckError('POSSIBLE_SECRET: '+name)
        payload[name]=data
    report={'status':'dry-run','target':m['target'],'files':[{'path':n,'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()} for n,d in payload.items()]}
    if a.write:
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
            for name,data in payload.items(): z.writestr(name,data)
        packed=buf.getvalue()
        with zipfile.ZipFile(io.BytesIO(packed)) as z:
            if z.testzip() is not None or any(z.read(n)!=d for n,d in payload.items()): raise CheckError('ZIP_VERIFY_FAILED')
        report.update(status='written',zipSha256=hashlib.sha256(packed).hexdigest())
        out.parent.mkdir(parents=True,exist_ok=True)
        created=[]
        try:
            with out.open('xb') as f:
                created.append(out); f.write(packed)
            with side.open('x') as f:
                created.append(side); json.dump(report,f,ensure_ascii=False,indent=2)
        except Exception:
            for p in created: p.unlink(missing_ok=True)
            raise
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','manifest','output'): p.add_argument('--'+name,required=True)
    p.add_argument('--write',action='store_true')
    a=p.parse_args()
    try: print(json.dumps(run(a),ensure_ascii=False));return 0
    except (CheckError,OSError,ValueError,TypeError) as e:
        # Never include JSON contents or arbitrary OS errors which might contain credentials.
        print(json.dumps({'status':'error','error':str(e) if isinstance(e,CheckError) else type(e).__name__}));return 1
if __name__=='__main__': sys.exit(main())
