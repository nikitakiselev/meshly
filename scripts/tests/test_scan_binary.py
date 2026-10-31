import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'scan-binary.py'
spec = importlib.util.spec_from_file_location('scan_binary', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class QualificationTests(unittest.TestCase):
    def test_clean_findings_pass(self):
        self.assertEqual(module.qualify([], ['crypto/x509']), [])

    def test_only_known_stripped_module_report_passes_without_openpgp(self):
        self.assertEqual(module.qualify([{'osv': 'GO-2026-5932'}], ['golang.org/x/crypto/curve25519']), ['GO-2026-5932'])

    def test_other_advisory_fails_even_alongside_known_report(self):
        with self.assertRaises(ValueError):
            module.qualify([{'osv': 'GO-2026-5932'}, {'osv': 'GO-2026-6809'}], ['crypto/x509'])

    def test_imported_openpgp_disables_exception(self):
        for package in ['golang.org/x/crypto/openpgp', 'golang.org/x/crypto/openpgp/armor']:
            with self.subTest(package=package), self.assertRaises(ValueError):
                module.qualify([{'osv': 'GO-2026-5932'}], [package])

    def test_malformed_finding_fails(self):
        with self.assertRaises(ValueError):
            module.qualify([{}], ['crypto/x509'])

if __name__ == '__main__':
    unittest.main()
