import importlib.util
import unittest
from pathlib import Path


class TestDay23InvestigationAPI(unittest.TestCase):

    def test_isolated_api_security_workflow(self):
        test_file = (
            Path(__file__).resolve().parent
            / "test_investigation_api.py"
        )

        spec = importlib.util.spec_from_file_location(
            "day23_original_security_tests",
            test_file
        )

        if spec is None or spec.loader is None:
            self.fail("Cannot load Day23 security tests")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        module.main()


if __name__ == "__main__":
    unittest.main()
