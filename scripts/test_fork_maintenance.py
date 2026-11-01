import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import sys
import unittest

SCRIPTS=pathlib.Path(__file__).resolve().parent

class CatalogMigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='csai-catalog-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        self.source=self.root/'source';self.install=self.root/'install'
        (self.source/'scripts').mkdir(parents=True);(self.source/'maintenance').mkdir()
        self.install.mkdir()
        shutil.copy2(SCRIPTS/'migrate-bundled-english.py',self.source/'scripts')
        (self.source/'roles').mkdir();(self.source/'roles/Default.yaml').write_text('name: Default\ndescription: English\n')
        self.old='name: legacy\ndescription: factory original\n'
        self.new=(self.source/'roles/Default.yaml').read_bytes()
        self.entry={'old_path':'roles/legacy.yaml','new_path':'roles/Default.yaml',
                    'original_sha256':hashlib.sha256(self.old.encode()).hexdigest(),
                    'english_sha256':hashlib.sha256(self.new).hexdigest()}
        (self.source/'maintenance/bundled-english.json').write_text(json.dumps({'files':[self.entry]}))
        (self.install/'roles').mkdir();(self.install/'roles/legacy.yaml').write_text(self.old)
        (self.install/'config.yaml').write_text('operator-secret: synthetic\n')
        (self.install/'data.db').write_bytes(b'persisted-customer-records')
    def run_cli(self,*args):
        return subprocess.run([sys.executable,str(self.source/'scripts/migrate-bundled-english.py'),'--install-root',str(self.install),*map(str,args)],text=True,capture_output=True)
    def test_dry_run_and_backed_up_factory_upgrade(self):
        result=self.run_cli();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.install/'roles/legacy.yaml').read_text(),self.old)
        self.assertFalse((self.install/'roles/Default.yaml').exists())
        backup=self.root/'backup'
        result=self.run_cli('--apply','--backup-dir',backup);self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.install/'roles/legacy.yaml').exists())
        self.assertEqual((self.install/'roles/Default.yaml').read_bytes(),self.new)
        self.assertEqual((backup/'roles/legacy.yaml').read_text(),self.old)
        self.assertEqual((self.install/'data.db').read_bytes(),b'persisted-customer-records')
        self.assertEqual((self.install/'config.yaml').read_text(),'operator-secret: synthetic\n')
        self.assertEqual(self.run_cli().returncode,0)
    def test_custom_content_blocks_before_any_write(self):
        custom='name: legacy\ndescription: operator custom\n'
        (self.install/'roles/legacy.yaml').write_text(custom)
        backup=self.root/'backup'
        result=self.run_cli('--apply','--backup-dir',backup)
        self.assertEqual(result.returncode,1)
        self.assertEqual((self.install/'roles/legacy.yaml').read_text(),custom)
        self.assertFalse(backup.exists())
    def test_replacement_integrity_checked(self):
        (self.source/'roles/Default.yaml').write_text('unreviewed replacement')
        result=self.run_cli('--apply','--backup-dir',self.root/'backup')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.install/'roles/legacy.yaml').read_text(),self.old)
    def test_missing_operator_deleted_default_is_not_recreated(self):
        (self.install/'roles/legacy.yaml').unlink()
        self.assertEqual(self.run_cli('--apply','--backup-dir',self.root/'backup').returncode,0)
        self.assertFalse((self.install/'roles/Default.yaml').exists())

    def test_destination_mutation_during_apply_is_never_overwritten(self):
        # Run the real CLI entry point, injecting a concurrent operator write
        # immediately after its old-file backup. Both destination states must
        # retain operator content and the still-recognized legacy source.
        for preexisting in [False, True]:
            with self.subTest(preexisting=preexisting):
                destination=self.install/'roles/Default.yaml'
                destination.unlink(missing_ok=True)
                if preexisting: destination.write_bytes(self.new)
                launcher = """import pathlib,runpy,shutil,sys
script,install,backup=sys.argv[1:]
original=shutil.copy2
def concurrent_write(src,dst,*args,**kwargs):
    result=original(src,dst,*args,**kwargs)
    if pathlib.Path(src).name=='legacy.yaml':
        (pathlib.Path(install)/'roles/Default.yaml').write_text('OPERATOR CUSTOM DURING APPLY')
    return result
shutil.copy2=concurrent_write
sys.argv=[script,'--install-root',install,'--apply','--backup-dir',backup]
runpy.run_path(script,run_name='__main__')
"""
                result=subprocess.run([sys.executable,'-c',launcher,str(self.source/'scripts/migrate-bundled-english.py'),str(self.install),str(self.root/('backup-'+str(preexisting)))],text=True,capture_output=True)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('destination changed after planning',result.stderr)
                self.assertEqual(destination.read_text(),'OPERATOR CUSTOM DURING APPLY')
                self.assertEqual((self.install/'roles/legacy.yaml').read_text(),self.old)

class ConfigScalarMigrationTest(unittest.TestCase):
    run_cli=CatalogMigrationTest.run_cli
    def setUp(self):
        CatalogMigrationTest.setUp(self)
        self.old_prompt='factory original prompt'
        self.new_prompt='English operational prompt'
        manifest_path=self.source/'maintenance/bundled-english.json'
        manifest=json.loads(manifest_path.read_text())
        manifest['config_scalars']=[{'path':['hitl','audit_agent_prompt'],
            'original_sha256':hashlib.sha256(self.old_prompt.encode()).hexdigest(),
            'english_sha256':hashlib.sha256(self.new_prompt.encode()).hexdigest(),
            'english_value':self.new_prompt}]
        manifest_path.write_text(json.dumps(manifest))
        self.config='operator-secret: SYNTHETIC-DO-NOT-PRINT\nhitl:\n  audit_agent_prompt: '+self.old_prompt+'\n'
        (self.install/'config.yaml').write_text(self.config)
    def test_only_recognized_scalar_changes_and_secret_bytes_stay(self):
        result=self.run_cli()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('SYNTHETIC-DO-NOT-PRINT',result.stdout+result.stderr)
        self.assertEqual((self.install/'config.yaml').read_text(),self.config)
        result=self.run_cli('--apply','--backup-dir',self.root/'backup')
        self.assertEqual(result.returncode,0,result.stderr)
        updated=(self.install/'config.yaml').read_text()
        self.assertIn('operator-secret: SYNTHETIC-DO-NOT-PRINT\n',updated)
        self.assertIn(self.new_prompt,updated)
        self.assertEqual((self.root/'backup/config.yaml').read_text(),self.config)
        self.assertEqual(self.run_cli().returncode,0)
    def test_customized_prompt_blocks_without_overwrite(self):
        custom=self.config.replace(self.old_prompt,'operator custom 约束')
        (self.install/'config.yaml').write_text(custom)
        result=self.run_cli('--apply','--backup-dir',self.root/'backup')
        self.assertEqual(result.returncode,1)
        self.assertEqual((self.install/'config.yaml').read_text(),custom)
        self.assertFalse((self.root/'backup').exists())
    def test_malformed_config_does_not_echo_its_contents(self):
        (self.install/'config.yaml').write_text('token: "SYNTHETIC-DO-NOT-PRINT\n')
        result=self.run_cli()
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('SYNTHETIC-DO-NOT-PRINT',result.stdout+result.stderr)

class UpstreamDryRunTest(unittest.TestCase):
    def git(self,path,*args):
        return subprocess.check_output(['git','-C',str(path),*args],text=True,stderr=subprocess.DEVNULL).strip()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='csai-upstream-test-');self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.fork=self.root/'fork';self.upstream=self.root/'upstream'
        self.fork.mkdir();self.git(self.fork,'init','--initial-branch=main')
        self.git(self.fork,'config','user.name','Fixture');self.git(self.fork,'config','user.email','fixture@invalid.example')
        (self.fork/'scripts').mkdir();shutil.copy2(SCRIPTS/'check-upstream.py',self.fork/'scripts')
        (self.fork/'shared').write_text('base\n');self.git(self.fork,'add','.');self.git(self.fork,'commit','-m','base')
        subprocess.run(['git','clone',str(self.fork),str(self.upstream)],check=True,capture_output=True)
        self.git(self.upstream,'config','user.name','Fixture');self.git(self.upstream,'config','user.email','fixture@invalid.example')
    def commit(self,path,file,content):
        (path/file).write_text(content);self.git(path,'add',file);self.git(path,'commit','-m','fixture change')
    def run_cli(self):
        return subprocess.run([sys.executable,str(self.fork/'scripts/check-upstream.py'),'--upstream',str(self.upstream)],text=True,capture_output=True)
    def test_clean_dry_run_preserves_fork_head_and_worktree(self):
        self.commit(self.fork,'fork-only','kept\n');self.commit(self.upstream,'vendor-only','incoming\n')
        head=self.git(self.fork,'rev-parse','HEAD');result=self.run_cli()
        self.assertEqual(result.returncode,0,result.stderr);report=json.loads(result.stdout)
        self.assertTrue(report['merge_clean']);self.assertFalse(report['promoted']);self.assertFalse(report['tests_run'])
        self.assertEqual(self.git(self.fork,'rev-parse','HEAD'),head)
        self.assertFalse((self.fork/'vendor-only').exists());self.assertEqual(self.git(self.fork,'status','--porcelain'),'')
    def test_conflict_report_preserves_source(self):
        self.commit(self.fork,'shared','fork\n');self.commit(self.upstream,'shared','vendor\n')
        head=self.git(self.fork,'rev-parse','HEAD');result=self.run_cli()
        self.assertEqual(result.returncode,1,result.stderr);report=json.loads(result.stdout)
        self.assertEqual(report['conflicts'],['shared']);self.assertFalse(report['merge_clean'])
        self.assertEqual(self.git(self.fork,'rev-parse','HEAD'),head)
        self.assertEqual((self.fork/'shared').read_text(),'fork\n')

if __name__=='__main__':unittest.main()
