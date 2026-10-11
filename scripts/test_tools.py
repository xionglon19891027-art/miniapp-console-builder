"""Isolated tests. Never load source projects or contact a service."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
TEST_APP_ID = 'wx' + ('0' * 16)

class ReleaseToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'source'
        self.root.mkdir()

    def file(self, name, data='ok'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def run_script(self, name, *args):
        return subprocess.run([sys.executable, '-B', str(HERE / name), *map(str, args)], capture_output=True, text=True)

    def manifest(self, files, target='backend', required=None):
        p = self.base / 'manifest.json'
        p.write_text(json.dumps(dict(schemaVersion=1, target=target, files=files, required=required or files)))
        return p

    def package(self, manifest, *extra):
        return self.run_script('package_release.py', '--root', self.root, '--manifest', manifest, '--output', self.base / 'output.zip', *extra)

    def miniapp(self):
        self.file('project.config.json', json.dumps({'appid':TEST_APP_ID,'miniprogramRoot':'miniapp/','packOptions':{'ignore':[{'type':'prefix','value':'._'}]}}))
        self.file('miniapp/app.json', json.dumps({'pages':['pages/home/home']}))
        self.file('miniapp/app.js', 'App({})')
        self.file('miniapp/pages/home/home.js', 'Page({})')
        self.file('miniapp/pages/home/home.wxml', '<view>Home</view>')

    def preflight(self, *extra):
        return self.run_script('miniapp_preflight.py','--root',self.root,'--api-base','https://api.acme.cn','--mode','experience',*extra)

    def test_dry_run_does_not_write(self):
        self.file('backend/main.py', 'print(1)')
        r = self.package(self.manifest(['backend/main.py']))
        self.assertEqual(r.returncode,0,r.stderr+r.stdout)
        self.assertFalse((self.base/'output.zip').exists())
        self.assertEqual(json.loads(r.stdout)['status'],'dry-run')

    def test_whitelist_zip_and_hashes(self):
        self.file('backend/main.py','print(1)'); self.file('backend/private.db','not to package')
        self.file('miniapp/app.js','not to package')
        manifest=self.manifest(['backend/main.py']); r=self.package(manifest,'--write')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        with zipfile.ZipFile(self.base/'output.zip') as z:
            self.assertEqual(z.namelist(),['backend/main.py']);self.assertEqual(z.read('backend/main.py'),b'print(1)')
        report=json.loads((self.base/'output.zip.manifest.json').read_text())
        self.assertEqual(len(report['files'][0]['sha256']),64)
        self.assertNotEqual(self.package(manifest,'--write').returncode,0)

    def test_reject_secret_without_echoing_value(self):
        secret='sk-'+('A'*40)
        self.file('backend/main.py','API_KEY = "'+secret+'"')
        r=self.package(self.manifest(['backend/main.py']),'--write')
        self.assertNotEqual(r.returncode,0);self.assertNotIn(secret,r.stdout+r.stderr)
        self.assertFalse((self.base/'output.zip').exists())

    def test_forbidden_files_and_cross_surface(self):
        for name in ['backend/.env','backend/x.sqlite-wal','backend/private.pem','backend/tests/test.py','pages/home.js','cloudfunctions/a.js','old.zip']:
            with self.subTest(name=name):
                self.file(name);self.assertNotEqual(self.package(self.manifest([name])).returncode,0)

    def test_escape_symlink_duplicate_and_required(self):
        self.file('backend/main.py')
        for files,required in [(['../outside'],None),(['/etc/passwd'],None),(['backend/main.py','backend/main.py'],None),(['backend/main.py'],['Dockerfile'])]:
            with self.subTest(files=files):self.assertNotEqual(self.package(self.manifest(files,required=required)).returncode,0)
        (self.root/'link.py').symlink_to(self.root/'backend/main.py')
        self.assertNotEqual(self.package(self.manifest(['link.py'])).returncode,0)

    def test_output_must_be_external(self):
        self.file('main.py')
        r=self.run_script('package_release.py','--root',self.root,'--manifest',self.manifest(['main.py']),'--output',self.root/'release.zip','--write')
        self.assertNotEqual(r.returncode,0);self.assertFalse((self.root/'release.zip').exists())

    def test_miniapp_ok_and_metadata_excluded(self):
        self.miniapp();self.file('miniapp/pages/._large','x'*1000)
        r=self.preflight('--source-budget-bytes','500')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        data=json.loads(r.stdout);self.assertEqual(data['ignoredFiles'],1)
        self.assertLess(data['sourceBytes'],500)
        self.assertEqual(data['platformUploadVerified'],False)

    def test_miniapp_detect_local_endpoint_and_secret(self):
        self.miniapp();self.file('miniapp/app.js','const API_BASE="http://192.168.1.50:8000";')
        r=self.preflight();self.assertNotEqual(r.returncode,0);self.assertIn('LOCAL_ENDPOINT',r.stdout)
        self.file('miniapp/app.js','const API_KEY="sk-'+('B'*40)+'";')
        r=self.preflight();self.assertNotEqual(r.returncode,0);self.assertNotIn('sk-'+('B'*40),r.stdout)

    def test_budget_and_missing_page(self):
        self.miniapp();self.assertNotEqual(self.preflight('--source-budget-bytes','1').returncode,0)
        (self.root/'miniapp/pages/home/home.wxml').unlink()
        self.assertIn('MISSING_PAGE',self.preflight().stdout)

    def test_empty_appid_and_unknown_ignore(self):
        self.miniapp();self.file('project.config.json',json.dumps({'appid':'touristappid','miniprogramRoot':'miniapp/','packOptions':{'ignore':[{'type':'mystery','value':'anything'}]}}))
        r=self.preflight();self.assertNotEqual(r.returncode,0);self.assertIn('IGNORE_UNSUPPORTED',r.stdout)

    def test_root_and_config_cannot_escape(self):
        self.file('project.config.json',json.dumps({'appid':TEST_APP_ID,'miniprogramRoot':'../outside'}))
        self.assertNotEqual(self.preflight().returncode,0)

    def test_cloud_function_and_parent_symlink(self):
        self.file('functions/handler.js', 'exports.main = async () => ({ok:true})')
        r=self.package(self.manifest(['functions/handler.js'],target='cloud-function'),'--write')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        (self.root/'alias').symlink_to(self.root/'functions',target_is_directory=True)
        r=self.run_script('package_release.py','--root',self.root,'--manifest',self.manifest(['alias/handler.js'],target='cloud-function'),'--output',self.base/'other.zip')
        self.assertEqual(json.loads(r.stdout)['error'],'SYMLINK')

    def test_rejections_are_structured(self):
        self.file('backend/main.py')
        r=self.package(self.manifest(['backend/main.py'],required=['missing.py']))
        self.assertEqual(json.loads(r.stdout)['error'],'REQUIRED_MISSING')
        r=self.package(self.manifest(['backend/main.py','backend/main.py']))
        self.assertEqual(json.loads(r.stdout)['error'],'DUPLICATE_FILE')

    def test_encoded_config_escape_and_uppercase_secret(self):
        self.miniapp()
        r=self.preflight('--config','../manifest.json')
        self.assertEqual(json.loads(r.stdout)['issues'][0]['code'],'INVALID_PATH')
        secret='UPPERCASESECRETVALUEABCDEF'
        self.file('backend/main.py','secret_key = "'+secret+'"')
        r=self.package(self.manifest(['backend/main.py']))
        self.assertIn('POSSIBLE_SECRET',r.stdout);self.assertNotIn(secret,r.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
