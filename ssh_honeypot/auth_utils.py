# -*- coding: utf-8 -*-
import hashlib


def secret_fingerprint(value: str) -> str:
    if value is None:
        return "none"
    if value == "":
        return "empty"
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return f"sha256:{digest[:12]}"
