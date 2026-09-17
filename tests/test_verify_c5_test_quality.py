#!/usr/bin/env python3
from __future__ import annotations
from datetime import datetime,timezone
import importlib.util,json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parent; NOW=datetime(2026,9,17,10,0,tzinfo=timezone.utc); BASE="1"*40; HEAD="2"*40
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class C5TestQualityR2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.v=load("v",ROOT/"verify_c5_test_quality.py"); cls.g=load("g",ROOT/"generate_c5_test_evidence.py")
    def build(self):
        run={"schema_version":"V3.2.1-C5-RAW-RUN-R1","runner":"unittest","runner_version":"3.9","base_sha":BASE,"head_sha":HEAD,"cases":[{"id":"test_red","classification":"valid_assertion_failure","failure_signature":"AssertionError: expected"},{"id":"test_green","classification":"passed","failure_signature":None}]}
        report={"policy":"V3.2.1-C5-AST-R1","file_flags":[],"tests":[{"id":"test_red","file":"tests/test_x.py","line":1,"quality":"valid","flags":[],"assertion_count":1},{"id":"test_green","file":"tests/test_x.py","line":5,"quality":"valid","flags":[],"assertion_count":1}]}
        artifacts={"run_1":json.dumps(run,sort_keys=True).encode(),"run_2":json.dumps(run,sort_keys=True).encode(),"ast_report":json.dumps(report,sort_keys=True).encode()}
        evidence=self.g.generate(repository="gg810612-pixel/v3-multi-agent-sandbox",observed_at="2026-09-17T09:00:00Z",valid_until="2026-09-17T21:00:00Z",base_sha=BASE,head_sha=HEAD,artifacts=artifacts,runner_policy={"command":"python -m unittest","no_tests_allowed":False,"snapshot_update_allowed":False},change_scope={"risk_level":"L2","changed_behavior":True,"direct_dependents_covered":True,"changed_lines_covered":True,"external_contract_fully_mocked":False},tests=[{"id":"test_red","file":"tests/test_x.py","line":1,"references_changed_behavior":True,"negative_test":None},{"id":"test_green","file":"tests/test_x.py","line":5,"references_changed_behavior":True,"negative_test":None}])
        return evidence,artifacts
    def test_safe(self):
        e,a=self.build(); self.assertEqual(self.v.verify(e,a,None,NOW)["valid_failure_ratio"],.5)
    def test_digest_recomputed(self):
        e,a=self.build(); a["run_1"]+=b" "
        with self.assertRaisesRegex(SystemExit,"artifact_digest_mismatch_run_1"): self.v.verify(e,a,None,NOW)
    def test_runs_repeat(self):
        e,a=self.build(); run=json.loads(a["run_2"]); run["cases"][0]["failure_signature"]="other"; a["run_2"]=json.dumps(run,sort_keys=True).encode(); e["artifacts"]["run_2"]["sha256"]=self.g.digest(a["run_2"])
        with self.assertRaisesRegex(SystemExit,"base_runs_not_repeatable"): self.v.verify(e,a,None,NOW)
    def test_no_test_escape(self):
        e,a=self.build(); e["runner_policy"]["command"]="jest --passWithNoTests"
        with self.assertRaisesRegex(SystemExit,"unsafe_runner_policy"): self.v.verify(e,a,None,NOW)
    def test_snapshot_update_escape(self):
        e,a=self.build(); e["runner_policy"]["snapshot_update_allowed"]=True
        with self.assertRaisesRegex(SystemExit,"unsafe_runner_policy"): self.v.verify(e,a,None,NOW)
    def test_ast_invalid_failure_does_not_count(self):
        e,a=self.build(); report=json.loads(a["ast_report"]); report["tests"][0]["quality"]="invalid"; report["tests"][0]["flags"]=["trivial_assertion"]; a["ast_report"]=json.dumps(report,sort_keys=True).encode(); e["artifacts"]["ast_report"]["sha256"]=self.g.digest(a["ast_report"])
        with self.assertRaisesRegex(SystemExit,"valid_failure_ratio_below_threshold"): self.v.verify(e,a,None,NOW)
    def test_inconclusive_ratio_exceeded(self):
        e,a=self.build()
        for name in ("run_1","run_2"):
            run=json.loads(a[name]); run["cases"][1]["classification"]="inconclusive_import"; a[name]=json.dumps(run,sort_keys=True).encode(); e["artifacts"][name]["sha256"]=self.g.digest(a[name])
        with self.assertRaisesRegex(SystemExit,"inconclusive_ratio_exceeded"): self.v.verify(e,a,None,NOW)
    def test_l3_requires_specific_negative(self):
        e,a=self.build(); e["change_scope"]["risk_level"]="L3"
        with self.assertRaisesRegex(SystemExit,"invalid_negative_test"): self.v.verify(e,a,None,NOW)
    def exception(self,actor="User"):
        e=self.g.generate(repository="gg810612-pixel/v3-multi-agent-sandbox",observed_at="2026-09-17T09:00:00Z",valid_until="2026-09-17T21:00:00Z",base_sha=BASE,head_sha=HEAD,artifacts={},runner_policy={"command":"not-run","no_tests_allowed":False,"snapshot_update_allowed":False},change_scope={"risk_level":"L1","changed_behavior":False,"direct_dependents_covered":True,"changed_lines_covered":True,"external_contract_fully_mocked":False},tests=[],exception_kind="docs-only")
        event={"kind":"docs-only","label":"docs-only","action":"added","actor_login":"human" if actor=="User" else "builder[bot]","actor_type":actor,"reason_comment_id":42,"reason":"docs only","pr_number":8,"head_sha":HEAD,"event_digest":"sha256:"+"a"*64}; return e,event
    def test_human_event_separate(self):
        e,event=self.exception(); self.assertEqual(self.v.verify(e,{},event,NOW)["exception"],"docs-only")
    def test_bot_event_fails(self):
        e,event=self.exception("Bot")
        with self.assertRaisesRegex(SystemExit,"authoritative_exception_user_required"): self.v.verify(e,{},event,NOW)
    def test_forged_actor_in_evidence_fails(self):
        e,event=self.exception(); e["exception_request"]["actor_type"]="User"
        with self.assertRaisesRegex(SystemExit,"invalid_exception_request"): self.v.verify(e,{},event,NOW)
if __name__=="__main__": unittest.main()
