#!/usr/bin/env python3
"""Verify digest-linked C5 R2 test evidence from base-produced artifacts."""
from __future__ import annotations
from datetime import datetime, timedelta
import hashlib, json, re
from typing import Any, NoReturn

POLICY="V3.2.1-C5-TEST-QUALITY-R2"; SCHEMA="V3.2.1-C5-EVIDENCE-R2"; REPOSITORY="gg810612-pixel/v3-multi-agent-sandbox"
VALID="valid_assertion_failure"; INCONCLUSIVE={"inconclusive_import","inconclusive_collection","inconclusive_fixture","inconclusive_timeout","inconclusive_environment"}; CLASSES={VALID,"passed",*INCONCLUSIVE}
SHA=re.compile(r"^[0-9a-f]{40}$"); DIGEST=re.compile(r"^sha256:[0-9a-f]{64}$")

def fail(reason:str)->NoReturn: raise SystemExit(f"C5_TEST_QUALITY=FAIL policy={POLICY} reason={reason}")
def exact(value:Any, keys:set[str], reason:str)->dict[str,Any]:
    if not isinstance(value,dict) or set(value)!=keys: fail(reason)
    return value
def time(value:Any, reason:str)->datetime:
    if not isinstance(value,str): fail(reason)
    value=value[:-1]+"+00:00" if value.endswith("Z") else value
    try: result=datetime.fromisoformat(value)
    except ValueError: fail(reason)
    if result.tzinfo is None: fail(reason)
    return result
def artifact(artifacts:dict[str,bytes], entries:dict[str,Any], name:str)->dict[str,Any]:
    raw=artifacts.get(name)
    if not isinstance(raw,bytes): fail(f"artifact_missing_{name}")
    entry=exact(entries.get(name),{"sha256"},f"invalid_artifact_entry_{name}")
    if entry["sha256"]!="sha256:"+hashlib.sha256(raw).hexdigest(): fail(f"artifact_digest_mismatch_{name}")
    try: value=json.loads(raw.decode())
    except (UnicodeDecodeError,json.JSONDecodeError): fail(f"artifact_json_invalid_{name}")
    if not isinstance(value,dict): fail(f"artifact_json_invalid_{name}")
    return value
def run_cases(run:dict[str,Any], base:str, head:str)->dict[str,tuple[str,str|None]]:
    run=exact(run,{"schema_version","runner","runner_version","base_sha","head_sha","cases"},"invalid_raw_run")
    if run["schema_version"]!="V3.2.1-C5-RAW-RUN-R1" or run["base_sha"]!=base or run["head_sha"]!=head: fail("raw_run_identity_mismatch")
    if not isinstance(run["cases"],list) or not run["cases"]: fail("raw_run_no_tests")
    out={}
    for raw in run["cases"]:
        case=exact(raw,{"id","classification","failure_signature"},"invalid_raw_case"); cid=case["id"]; classification=case["classification"]; signature=case["failure_signature"]
        if not isinstance(cid,str) or not cid or cid in out or classification not in CLASSES: fail("invalid_raw_case")
        if classification==VALID and (not isinstance(signature,str) or not signature.strip()): fail("invalid_failure_signature")
        if classification!=VALID and signature is not None: fail("invalid_failure_signature")
        out[cid]=(classification,signature)
    return out
def authoritative_exception(event:Any, kind:str, head:str)->None:
    event=exact(event,{"kind","label","action","actor_login","actor_type","reason_comment_id","reason","pr_number","head_sha","event_digest"},"authoritative_exception_event_required")
    if event["kind"]!=kind or event["label"]!=kind or event["action"]!="added" or event["head_sha"]!=head: fail("authoritative_exception_event_mismatch")
    if event["actor_type"]!="User" or not isinstance(event["actor_login"],str) or not event["actor_login"]: fail("authoritative_exception_user_required")
    if not isinstance(event["reason_comment_id"],int) or isinstance(event["reason_comment_id"],bool) or event["reason_comment_id"]<1 or not isinstance(event["reason"],str) or not event["reason"].strip(): fail("authoritative_exception_reason_required")
    if not isinstance(event["pr_number"],int) or event["pr_number"]<1 or not isinstance(event["event_digest"],str) or DIGEST.fullmatch(event["event_digest"]) is None: fail("authoritative_exception_event_mismatch")
def verify(evidence:dict[str,Any], artifacts:dict[str,bytes], authoritative_event:dict[str,Any]|None, now:datetime)->dict[str,Any]:
    top=exact(evidence,{"schema_version","repository","observed_at","valid_until","base_sha","head_sha","artifacts","runner_policy","change_scope","exception_request","tests"},"invalid_evidence")
    if top["schema_version"]!=SCHEMA or top["repository"]!=REPOSITORY: fail("invalid_evidence_identity")
    observed,until=time(top["observed_at"],"invalid_observed_at"),time(top["valid_until"],"invalid_valid_until")
    if not observed<=now<=until or until-observed>timedelta(hours=24): fail("evidence_stale_or_invalid")
    base,head=top["base_sha"],top["head_sha"]
    if not isinstance(base,str) or not isinstance(head,str) or SHA.fullmatch(base) is None or SHA.fullmatch(head) is None or base==head: fail("invalid_sha")
    scope=exact(top["change_scope"],{"risk_level","changed_behavior","direct_dependents_covered","changed_lines_covered","external_contract_fully_mocked"},"invalid_change_scope")
    if scope["risk_level"] not in {"L1","L2","L3"}: fail("invalid_change_scope")
    request=exact(top["exception_request"],{"kind"},"invalid_exception_request"); kind=request["kind"]
    if kind is not None:
        if kind not in {"refactor-only","docs-only"} or scope["changed_behavior"] or top["tests"] or top["artifacts"] or artifacts: fail("invalid_exception_request")
        authoritative_exception(authoritative_event,kind,head); return {"exception":kind,"valid_failure_ratio":1.0,"inconclusive_ratio":0.0}
    if authoritative_event is not None: fail("unexpected_authoritative_exception_event")
    if not scope["changed_behavior"] or not scope["direct_dependents_covered"] or not scope["changed_lines_covered"] or scope["external_contract_fully_mocked"]: fail("change_scope_not_satisfied")
    policy=exact(top["runner_policy"],{"command","no_tests_allowed","snapshot_update_allowed"},"invalid_runner_policy")
    command=policy["command"]
    if not isinstance(command,str) or not command or policy["no_tests_allowed"] is not False or policy["snapshot_update_allowed"] is not False or any(flag in command.casefold() for flag in ("passwithnotests","allow-empty","--update-snapshots")): fail("unsafe_runner_policy")
    entries=exact(top["artifacts"],{"run_1","run_2","ast_report"},"invalid_artifacts")
    first=run_cases(artifact(artifacts,entries,"run_1"),base,head); second=run_cases(artifact(artifacts,entries,"run_2"),base,head)
    report=exact(artifact(artifacts,entries,"ast_report"),{"policy","tests","file_flags"},"invalid_ast_report")
    if report["policy"]!="V3.2.1-C5-AST-R1" or "no_tests" in report["file_flags"]: fail("invalid_ast_report")
    ast_cases={case.get("id"):case for case in report["tests"] if isinstance(case,dict)}; tests=top["tests"]
    if not isinstance(tests,list) or not tests: fail("no_changed_tests")
    ids={case.get("id") for case in tests if isinstance(case,dict)}
    if ids!=set(first) or ids!=set(second) or ids!=set(ast_cases) or None in ids: fail("artifact_test_set_mismatch")
    valid_count=inconclusive=0; valid_negative=False
    for raw in tests:
        case=exact(raw,{"id","file","line","references_changed_behavior","negative_test"},"invalid_test_case"); cid=case["id"]; ast_case=ast_cases[cid]
        if case["file"]!=ast_case.get("file") or case["line"]!=ast_case.get("line"): fail("ast_linkage_mismatch")
        a,b=first[cid],second[cid]
        if a[0] in INCONCLUSIVE or b[0] in INCONCLUSIVE: inconclusive+=1; continue
        if a!=b: fail("base_runs_not_repeatable")
        valid=a[0]==VALID and ast_case.get("quality")=="valid" and ast_case.get("flags")==[] and case["references_changed_behavior"] is True
        if valid: valid_count+=1
        negative=case["negative_test"]
        if negative is not None:
            negative=exact(negative,{"exception_type","message_fragment","data_related"},"invalid_negative_test")
            if not valid or negative["exception_type"] in {"Exception","BaseException",""} or not isinstance(negative["message_fragment"],str) or not negative["message_fragment"].strip() or negative["data_related"] is not True: fail("invalid_negative_test")
            valid_negative=True
    total=len(tests); vr=valid_count/total; ir=inconclusive/total
    if ir>0.2: fail("inconclusive_ratio_exceeded")
    if vr<0.5: fail("valid_failure_ratio_below_threshold")
    if scope["risk_level"]=="L3" and not valid_negative: fail("invalid_negative_test")
    return {"test_count":total,"valid_failure_count":valid_count,"inconclusive_count":inconclusive,"valid_failure_ratio":vr,"inconclusive_ratio":ir}
