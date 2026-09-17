#!/usr/bin/env python3
"""Tests for the C5 static assertion-quality scanner."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "scan_c5_test_assertions.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("c5_ast_scanner", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load C5 AST scanner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class C5AssertionScannerTests(unittest.TestCase):
    def test_data_linked_assertion_is_valid(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "def test_denied():\n    result = authorize('builder')\n    assert result == 'denied'\n",
            "test_auth.py",
        )
        self.assertEqual(report["tests"][0]["quality"], "valid")

    def test_assert_true_and_constant_comparison_are_trivial(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "def test_fake():\n    assert True\n    assert 1 == 1\n",
            "test_fake.py",
        )
        self.assertEqual(report["tests"][0]["quality"], "invalid")
        self.assertIn("trivial_assertion", report["tests"][0]["flags"])

    def test_response_not_none_only_is_invalid(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "def test_weak():\n    response = call_api()\n    assert response is not None\n",
            "test_api.py",
        )
        self.assertEqual(report["tests"][0]["quality"], "invalid")
        self.assertIn("response_not_none_only", report["tests"][0]["flags"])

    def test_bare_exception_negative_is_invalid(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "def test_negative(self):\n    with self.assertRaises(Exception):\n        authorize('builder')\n",
            "test_auth.py",
        )
        self.assertEqual(report["tests"][0]["quality"], "invalid")
        self.assertIn("bare_exception", report["tests"][0]["flags"])

    def test_imports_are_not_executed(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "from module_that_does_not_exist import x\n\ndef test_fake():\n    assert True\n",
            "test_import.py",
        )
        self.assertEqual(report["tests"][0]["quality"], "invalid")

    def test_specific_exception_and_message_is_valid(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "def test_negative(self):\n    with self.assertRaisesRegex(PermissionError, 'denied'):\n        authorize('builder')\n",
            "test_auth.py",
        )
        self.assertEqual(report["tests"][0]["quality"], "valid")
        self.assertEqual(report["tests"][0]["assertion_count"], 1)

    def test_unittest_constant_and_self_equality_assertions_are_invalid(self) -> None:
        scanner = load_scanner()
        sources = (
            "def test_x(self):\n    self.assertTrue(True)\n",
            "def test_x(self):\n    self.assertEqual(1, 1)\n",
            "def test_x(self):\n    self.assertIsNotNone(response)\n",
            "def test_x():\n    result = call()\n    assert result == result\n",
        )
        for source in sources:
            with self.subTest(source=source):
                report = scanner.scan_source(source, "test_x.py")
                self.assertEqual(report["tests"][0]["quality"], "invalid")

    def test_empty_assert_raises_regex_is_invalid(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source(
            "def test_x(self):\n    with self.assertRaisesRegex(ValueError, ''):\n        call()\n",
            "test_x.py",
        )
        self.assertIn("empty_exception_regex", report["tests"][0]["flags"])

    def test_file_without_tests_is_reported(self) -> None:
        scanner = load_scanner()
        report = scanner.scan_source("def helper():\n    return True\n", "helpers.py")
        self.assertEqual(report["tests"], [])
        self.assertIn("no_tests", report["file_flags"])


if __name__ == "__main__":
    unittest.main()
