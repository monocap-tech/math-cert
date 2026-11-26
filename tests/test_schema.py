import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/obligation-v1.json").read_text())
DEMO = json.loads((ROOT / "examples/obligation.demo.json").read_text())


class TestObligationSchema(unittest.TestCase):
    def setUp(self):
        self.validator = Draft202012Validator(SCHEMA)
        self.sample = copy.deepcopy(DEMO)

    def test_schema_is_valid(self):
        Draft202012Validator.check_schema(SCHEMA)

    def test_example(self):
        self.validator.validate(self.sample)

    def test_missing_scope(self):
        del self.sample["claim"]["scope_limits"]
        with self.assertRaises(ValidationError):
            self.validator.validate(self.sample)

    def test_unpinned_source(self):
        self.sample["sources"][0]["commit"] = "main"
        with self.assertRaises(ValidationError):
            self.validator.validate(self.sample)

    def test_fake_acceptance_status(self):
        self.sample["accepted"] = True
        with self.assertRaises(ValidationError):
            self.validator.validate(self.sample)

    def test_invalid_environment_digest(self):
        self.sample["verification"]["environment_digest"] = "latest"
        with self.assertRaises(ValidationError):
            self.validator.validate(self.sample)

    def test_dependency_requires_exact_receipt(self):
        self.sample["dependencies"] = [{"id": "DEMO.Parent"}]
        with self.assertRaises(ValidationError):
            self.validator.validate(self.sample)

    def test_empty_sources(self):
        self.sample["sources"] = []
        with self.assertRaises(ValidationError):
            self.validator.validate(self.sample)


if __name__ == "__main__":
    unittest.main()
