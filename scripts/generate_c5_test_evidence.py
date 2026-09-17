#!/usr/bin/env python3
"""Generate C5 R2 evidence without accepting preclassified evidence fields."""
from __future__ import annotations
import hashlib, json
from typing import Any
def digest(raw:bytes)->str: return "sha256:"+hashlib.sha256(raw).hexdigest()
def generate(*,repository:str,observed_at:str,valid_until:str,base_sha:str,head_sha:str,artifacts:dict[str,bytes],runner_policy:dict[str,Any],change_scope:dict[str,Any],tests:list[dict[str,Any]],exception_kind:str|None=None)->dict[str,Any]:
    return {"schema_version":"V3.2.1-C5-EVIDENCE-R2","repository":repository,"observed_at":observed_at,"valid_until":valid_until,"base_sha":base_sha,"head_sha":head_sha,"artifacts":{name:{"sha256":digest(raw)} for name,raw in sorted(artifacts.items())},"runner_policy":runner_policy,"change_scope":change_scope,"exception_request":{"kind":exception_kind},"tests":tests}
def canonical_bytes(value:dict[str,Any])->bytes: return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
