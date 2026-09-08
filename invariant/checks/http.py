"""http check: request a URL, assert on its status code and/or a substring
in the response body.

stdlib only (urllib) -- the same reasoning as sql's sqlite3 path: this is
the trivial, no-extra-dependency case, not a general HTTP testing tool.

Args:
    url: the URL to GET
    expect_status: status code that must match (optional, default: any 2xx)
    expect_contains: substring that must appear in the response body (optional)
    timeout: seconds (default 10)
"""
from __future__ import annotations

import urllib.error
import urllib.request

from ..model import FAIL, PASS, UNVERIFIED

_USER_AGENT = "invariant-verify/http-check (+https://github.com/MaXiMo000/invariant)"


def run(args: dict) -> tuple[str, str, dict]:
    url = args["url"]
    expect_status = args.get("expect_status")
    expect_contains = args.get("expect_contains")
    timeout = args.get("timeout", 10)

    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # An HTTP error status is a real, checkable response -- not a
        # failure to reach the URL at all -- so it's not unverified.
        status = exc.code
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
    except Exception as exc:  # noqa: BLE001 - couldn't reach it at all: unverified, not a crash
        return UNVERIFIED, f"could not reach {url}: {exc}", {"url": url}

    # The response body is never written into evidence whole -- it could
    # be arbitrarily large or carry something sensitive from a real
    # endpoint; only its length and whether the expected substring was
    # found are evidence-worthy here.
    evidence = {"url": url, "status": status, "body_length": len(body)}

    problems = []
    if expect_status is not None and status != expect_status:
        problems.append(f"status {status}, expected {expect_status}")
    elif expect_status is None and not (200 <= status < 300):
        problems.append(f"status {status}, expected 2xx")
    if expect_contains is not None and expect_contains not in body:
        problems.append(f"response body did not contain {expect_contains!r}")
        evidence["expect_contains"] = expect_contains

    if problems:
        return FAIL, "; ".join(problems), evidence
    detail = f"status {status}"
    if expect_contains is not None:
        detail += f", body contains {expect_contains!r}"
    return PASS, detail, evidence
