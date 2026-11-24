"""Keep the new ESO IAM/bootstrap contracts in the existing offline CI gate."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EsoCIContractTests(unittest.TestCase):
    def test_offline_workflow_runs_the_new_contracts(self):
        workflow = (ROOT / '.github/workflows/validate.yml').read_text()
        for required in ('tests/requirements-eso-iam.txt',
                         'talos-secrets-bootstrap.yml',
                         'tests/test_talos_eso_iam.py',
                         'tests/test_talos_secrets_bootstrap.py',
                         'tests/test_eso_ci_contract.py'):
            with self.subTest(required=required):
                self.assertIn(required, workflow)


if __name__ == '__main__':
    unittest.main()
