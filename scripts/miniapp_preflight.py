"""Read-only source preflight; does not measure the platform compiled package."""
import argparse
import json
from pathlib import Path
import re
import sys
from checks import CheckError, safe_path, forbidden, has_secret, public_https, local_endpoint

def run(a):
    root=Path(a.root).resolve(strict=True)
    config=json.loads(safe_path(root,a.config).read_text())
    rel=config.get('miniprogramRoot','').rstrip('/')
    mini=safe_path(root,rel) if rel and rel!='.' else root
    if not mini.is_dir(): raise CheckError('INVALID_MINIPROGRAM_ROOT')
    issues=[]
    def issue(code,path=None,level='error'):
        item={'code':code,'level':level}
        if path: item['path']=path
        issues.append(item)
    if a.mode!='development' and not re.fullmatch(r'wx[0-9a-fA-F]{16}',str(config.get('appid',''))): issue('INVALID_APPID')
    if a.mode!='development' and not public_https(a.api_base): issue('API_REQUIRES_PUBLIC_HTTPS')
    rules=config.get('packOptions',{}).get('ignore',[])
    supported=[]
    for rule in rules:
        if not isinstance(rule,dict) or rule.get('type') not in {'prefix','suffix','file','folder'} or not isinstance(rule.get('value'),str):
            issue('IGNORE_UNSUPPORTED',level='warning');continue
        supported.append(rule)
    def ignored(name):
        for r in supported:
            v=r['value'].strip('/');t=r['type']
            if (t=='file' and name==v) or (t=='folder' and (name==v or name.startswith(v+'/'))) or (t=='prefix' and (name.startswith(v) or Path(name).name.startswith(v))) or (t=='suffix' and name.endswith(v)): return True
        return False
    included=set();size=0;skipped=0
    for path in sorted(mini.rglob('*')):
        name=path.relative_to(mini).as_posix()
        if ignored(name):
            if path.is_file(): skipped+=1
            continue
        if path.is_symlink(): issue('SYMLINK',name);continue
        if not path.is_file(): continue
        safe_path(mini,name)
        data=path.read_bytes();included.add(name);size+=len(data)
        if forbidden(name): issue('SENSITIVE_OR_NONRUNTIME_FILE',name)
        if has_secret(data): issue('POSSIBLE_SECRET',name)
        if a.mode!='development' and local_endpoint(data): issue('LOCAL_ENDPOINT',name)
    if size>a.source_budget_bytes: issue('SOURCE_BUDGET_EXCEEDED')
    if 'app.json' not in included: issue('MISSING_APP_JSON')
    else:
        app=json.loads((mini/'app.json').read_text())
        pages=list(app.get('pages',[]))
        for sub in app.get('subPackages',app.get('subpackages',[])):
            pages.extend(sub['root'].rstrip('/')+'/'+p for p in sub.get('pages',[]))
        if not pages: issue('NO_PAGES')
        for page in pages:
            safe_path(mini,page)
            for ext in ('.js','.wxml'):
                if page+ext not in included: issue('MISSING_PAGE',page+ext)
    return {'status':'failed' if any(i['level']=='error' for i in issues) else 'passed','sourceBytes':size,'ignoredFiles':skipped,'platformUploadVerified':False,'issues':issues,'limitations':['源码字节不等于编译上传体积','API地址为声明值，未验证实际运行配置、域名白名单或网络','离线规则不覆盖完整安全审计、组件依赖和云SDK授权']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',required=True);p.add_argument('--config',default='project.config.json');p.add_argument('--api-base',required=True)
    p.add_argument('--mode',choices=['development','experience','release'],default='experience')
    p.add_argument('--source-budget-bytes',type=int,default=1887436)
    a=p.parse_args()
    try:
        r=run(a);print(json.dumps(r,ensure_ascii=False));return 1 if r['status']=='failed' else 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        print(json.dumps({'status':'failed','platformUploadVerified':False,'issues':[{'code':str(e) if isinstance(e,CheckError) else type(e).__name__}]}));return 1
if __name__=='__main__':sys.exit(main())
