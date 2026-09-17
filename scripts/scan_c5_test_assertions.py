#!/usr/bin/env python3
"""Static, non-executing assertion-quality scanner for C5."""

from __future__ import annotations

import argparse
import ast
import json
import operator
from pathlib import Path
from typing import Any


POLICY = "V3.2.1-C5-AST-R1"


def dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def constant_truth(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is True
    if isinstance(node, ast.Compare):
        values = [node.left, *node.comparators]
        operations = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.Is: operator.is_,
            ast.IsNot: operator.is_not,
        }
        if all(isinstance(value, ast.Constant) for value in values):
            for index, comparison in enumerate(node.ops):
                operation = operations.get(type(comparison))
                if operation is None or not operation(values[index].value, values[index + 1].value):
                    return False
            return True
    return False


def response_not_none(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], (ast.Is, ast.IsNot)):
        return False
    right = node.comparators[0]
    if not isinstance(right, ast.Constant) or right.value is not None:
        return False
    return dotted_name(node.left).split(".")[0] == "response"


def same_expression_comparison(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and len(node.comparators) == 1
        and ast.dump(node.left, include_attributes=False)
        == ast.dump(node.comparators[0], include_attributes=False)
    )


def invalid_unittest_assertion(node: ast.Call) -> str | None:
    name = dotted_name(node.func)
    if name == "self.assertTrue" and node.args and constant_truth(node.args[0]):
        return "trivial_assertion"
    if name in {"self.assertEqual", "self.assertIs"} and len(node.args) >= 2:
        if ast.dump(node.args[0], include_attributes=False) == ast.dump(node.args[1], include_attributes=False):
            return "self_equality_assertion"
        if all(isinstance(argument, ast.Constant) for argument in node.args[:2]):
            return "trivial_assertion"
    if name == "self.assertIsNotNone" and node.args:
        return "non_null_only_assertion"
    return None


def bare_exception_context(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call) or not node.args:
        return False
    name = dotted_name(node.func)
    if name not in {"self.assertRaises", "unittest.TestCase.assertRaises", "pytest.raises"}:
        return False
    return dotted_name(node.args[0]) in {"Exception", "BaseException"}


def raises_context(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call) or not node.args:
        return False
    return dotted_name(node.func) in {
        "self.assertRaises",
        "self.assertRaisesRegex",
        "unittest.TestCase.assertRaises",
        "unittest.TestCase.assertRaisesRegex",
        "pytest.raises",
    }


def scan_test(function: ast.AST, filename: str) -> dict[str, Any]:
    flags: set[str] = set()
    assertion_count = 0
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            assertion_count += 1
            if constant_truth(node.test):
                flags.add("trivial_assertion")
            if response_not_none(node.test):
                flags.add("response_not_none_only")
            if same_expression_comparison(node.test):
                flags.add("self_equality_assertion")
        elif isinstance(node, ast.With):
            for item in node.items:
                if raises_context(item.context_expr):
                    assertion_count += 1
                    if (
                        isinstance(item.context_expr, ast.Call)
                        and dotted_name(item.context_expr.func).endswith("assertRaisesRegex")
                        and len(item.context_expr.args) >= 2
                        and isinstance(item.context_expr.args[1], ast.Constant)
                        and item.context_expr.args[1].value == ""
                    ):
                        flags.add("empty_exception_regex")
                if bare_exception_context(item.context_expr):
                    flags.add("bare_exception")
        elif isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name.startswith("self.assert") and name not in {
                "self.assertRaises",
                "self.assertRaisesRegex",
            }:
                assertion_count += 1
                invalid = invalid_unittest_assertion(node)
                if invalid:
                    flags.add(invalid)
    if assertion_count == 0:
        flags.add("no_assertion")
    return {
        "id": getattr(function, "name"),
        "file": filename,
        "line": getattr(function, "lineno"),
        "assertion_count": assertion_count,
        "flags": sorted(flags),
        "quality": "valid" if not flags else "invalid",
    }


def scan_source(source: str, filename: str) -> dict[str, Any]:
    tree = ast.parse(source, filename=filename)
    tests = [
        scan_test(node, filename)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    ]
    tests.sort(key=lambda item: (item["file"], item["line"], item["id"]))
    return {"policy": POLICY, "tests": tests, "file_flags": [] if tests else ["no_tests"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    reports = []
    for raw_path in args.paths:
        target = Path(raw_path)
        reports.append(scan_source(target.read_text(encoding="utf-8"), str(target)))
    print(json.dumps({"policy": POLICY, "reports": reports}, sort_keys=True))


if __name__ == "__main__":
    main()
