#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parent
class GeneratorTests(unittest.TestCase):
    def test_hashes_raw_data_without_actor_or_classification(self):
        spec=importlib.util.spec_from_file_location("g",ROOT/"generate_c5_test_evidence.py"); g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
        e=g.generate(repository="repo",observed_at="now",valid_until="later",base_sha="1"*40,head_sha="2"*40,artifacts={"run_1":b"{}"},runner_policy={},change_scope={},tests=[])
        self.assertEqual(e["artifacts"]["run_1"]["sha256"],g.digest(b"{}")); self.assertNotIn("actor_type",str(e)); self.assertNotIn("classification",str(e))
if __name__=="__main__": unittest.main()
