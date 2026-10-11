"""Conservative offline checks; never prints matched credentials."""
import ipaddress
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

class CheckError(ValueError):
    pass

def safe_path(root, value):
    if not isinstance(value, str) or not value or '\\' in value or any(ord(c)<32 for c in value) or any(c in value for c in '*?[]'):
        raise CheckError('INVALID_PATH')
    p=PurePosixPath(value)
    if p.is_absolute() or any(x in ('', '.', '..') for x in value.split('/')):
        raise CheckError('INVALID_PATH')
    result=root
    for part in p.parts:
        result=result/part
        if result.is_symlink(): raise CheckError('SYMLINK')
    if not result.resolve().is_relative_to(root): raise CheckError('PATH_ESCAPE')
    return result

def forbidden(value, target=None):
    p=PurePosixPath(value); parts=[s.lower() for s in p.parts]; name=parts[-1]
    banned={'node_modules','__pycache__','.git','.venv','venv','tests','test','docs','__macosx'}
    if any(s in banned or s.startswith('._') for s in parts): return True
    if name.startswith('.env') or name in {'.ds_store','credentials.json','ai.env','cloudbase.env'}: return True
    if re.search(r'\.(?:db|sqlite|sqlite3)(?:-wal|-shm|-journal)?$|\.(?:pem|key|p12|pfx|pyc|zip|tar|gz|7z)$',name): return True
    return target=='backend' and parts[0] in {'miniapp','miniprogram','pages','utils','cloudfunctions'}

SECRET_PATTERNS=[
    re.compile(rb'\bsk-[A-Za-z0-9_-]{20,}'),
    re.compile(rb'\bAKID[A-Za-z0-9]{20,}'),
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password)\s*[:=]\s*[\"\x27]([^\"\x27\r\n]{8,})[\"\x27]'),
]
def has_secret(data):
    for pattern in SECRET_PATTERNS:
        for m in pattern.finditer(data):
            value=m.group(1) if m.lastindex else m.group(0)
            if m.lastindex and (value.lower() in {b'change_me',b'your_api_key',b'your_secret_key',b'replace_me',b'placeholder'}): continue
            return True
    return False

def public_https(value):
    try:
        u=urlsplit(value)
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.fragment or u.query: return False
        host=u.hostname.lower().rstrip('.')
        if host in {'localhost','example.com','example.org','example.net'} or host.endswith(('.localhost','.local','.internal','.example.com','.example.org','.example.net')): return False
        try: return ipaddress.ip_address(host).is_global
        except ValueError: return bool(re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}',host))
    except ValueError: return False

def local_endpoint(data):
    for m in re.finditer(rb'https?://([^/\s\"\x27<>]+)',data):
        try:
            host=urlsplit(m.group(0).decode()).hostname or ''
            if host.lower()=='localhost' or host.lower().endswith(('.local','.localhost','.internal')): return True
            try:
                if not ipaddress.ip_address(host).is_global: return True
            except ValueError: pass
        except (ValueError,UnicodeError): pass
    return False
