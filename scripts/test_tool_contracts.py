"""Exercise the reviewed declarative CLI contract through its executable checker."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name('check-tool-contracts.py')

class ToolContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='csai-contract-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root/'tools').mkdir()
        (self.root/'maintenance').mkdir()
        self.path = self.root/'tools/fixture.yaml'
        self.path.write_text('name: fixture\ncommand: python3\nargs: ["-c", "print(\\\"English fixture\\\")"]\nenabled: false\ndescription: English metadata\nparameters: []\n')
        result = self.cli('--write-reviewed')
        self.assertEqual(result.returncode, 0, result.stderr)
    def cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root), *args], capture_output=True, text=True)
    def test_metadata_edit_preserves_machine_contract(self):
        self.path.write_text(self.path.read_text().replace('English metadata', 'Reviewed English description'))
        self.assertEqual(self.cli().returncode, 0)
    def test_enablement_change_requires_contract_review(self):
        self.path.write_text(self.path.read_text().replace('enabled: false', 'enabled: true'))
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertIn('fixture.yaml', result.stdout)
    def test_non_english_recipe_is_rejected_without_execution(self):
        marker = self.root/'must-not-exist'
        self.path.write_text('name: fixture\ncommand: python3\nargs:\n  - -c\n  - |\n    from pathlib import Path\n    Path('+repr(str(marker))+').write_text("not executed")\n    print("\\u4e2d\\u6587")\nenabled: false\nparameters: []\n')
        result = self.cli('--write-reviewed')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('untranslated bundled executable literal', result.stderr)
        self.assertFalse(marker.exists())

if __name__ == '__main__':
    unittest.main()
