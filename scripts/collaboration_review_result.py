"""Prepare an admitted final review from an already authenticated model result.

This is an in-process adapter for a trusted protected controller, not an
authentication endpoint or native acceptance proof. The caller authenticates
the provider receipt, source, current PR and generation before calling it and
supplies the actual reviewed-head line map. Only the separate publisher owns
credentials, operation reservations and transport reconciliation.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import collaboration_content as content
import exact_revision_gateway as gateway

MAX_FINDINGS = 100
MAX_TEXT = 65536


def require(condition, category):
    content.require(condition, category)


def _path(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 1024,
            "review-path")
    require(not value.startswith("/") and "\\" not in value
            and all(part not in ("", ".", "..") for part in value.split("/"))
            and not any(ord(char) < 32 for char in value), "review-path")


def _text(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= MAX_TEXT,
            "review-text-size")


def final_review_payload(result, metadata, subject, reviewed_lines):
    """Render all findings without inventing inline positions or review authority.

    `subject` is independent trusted workflow input, not provider-controlled
    metadata. `reviewed_lines` is obtained from the authenticated exact-head
    review input, mapping each reviewed path to its commentable RIGHT lines.
    Null/non-commentable positions remain in the body; unknown paths fail.
    """
    try:
        require(type(subject) is dict and set(subject) == {
            "repository", "repository_id", "pull_request", "head_sha", "source_sha"},
            "review-subject")
        require(type(subject["repository"]) is str
                and re.fullmatch(r"ltn-it/[A-Za-z0-9_.-]+", subject["repository"])
                and type(subject["repository_id"]) is int and subject["repository_id"] > 0
                and type(subject["pull_request"]) is int and subject["pull_request"] > 0,
                "review-subject")
        for key in ("head_sha", "source_sha"):
            require(type(subject[key]) is str and re.fullmatch(r"[0-9a-f]{40}", subject[key]),
                    "review-subject")
        require(type(metadata) is dict
                and metadata.get("repository") == subject["repository"]
                and metadata.get("pull_request") == subject["pull_request"]
                and type(metadata.get("pull_request")) is int
                and metadata.get("head_sha") == subject["head_sha"]
                and metadata.get("central_source_sha") == subject["source_sha"],
                "review-subject-binding")
        for key in gateway.BINDINGS:
            require(type(metadata.get(key)) is str
                    and re.fullmatch(r"[0-9a-f]{%d}" % (64 if key.endswith("sha256") else 40),
                                     metadata[key]), "review-metadata")
        require(type(reviewed_lines) is dict and len(reviewed_lines) <= 10000, "review-lines")
        lines = {}
        for path, positions in reviewed_lines.items():
            _path(path)
            require(type(positions) in (list, tuple, set, frozenset)
                    and len(positions) <= 100000
                    and all(type(line) is int and line >= 1 for line in positions), "review-lines")
            lines[path] = frozenset(positions)
        require(type(result) is dict and type(result.get("findings")) is list
                and len(result["findings"]) <= MAX_FINDINGS, "review-result")
        _text(result.get("summary"))
        for finding in result["findings"]:
            require(type(finding) is dict, "review-finding")
            _path(finding.get("path"))
            for key in ("title", "body"):
                _text(finding.get(key))
        # Freeze plain data before validation/rendering; callers cannot change
        # the result while a transport later consumes the final bytes.
        packet = json.loads(json.dumps(result, allow_nan=False))
        gateway.validate_result(packet, metadata)
        body = ["## Protected review result", "", "Verdict: " + packet["verdict"],
                "", packet["summary"]]
        comments = []
        if packet["findings"]:
            body += ["", "### Findings"]
        for ordinal, finding in enumerate(packet["findings"], 1):
            path, line = finding["path"], finding["line"]
            require(path in lines, "review-path-outside-subject")
            heading = finding["severity"].upper() + ": " + finding["title"]
            location = "Path: `" + path + "`"
            if line is not None:
                location += "; line: " + str(line)
            body += ["", str(ordinal) + ". " + heading, "", location, "", finding["body"]]
            if line is not None and line in lines[path]:
                comments.append({"path": path, "line": line, "side": "RIGHT",
                                 "body": heading + "\n\n" + finding["body"]})
        payload = {"commit_id": subject["head_sha"], "event": "COMMENT",
                   "body": "\n".join(body)}
        if comments:
            payload["comments"] = comments
        return payload
    except content.AdmissionError:
        raise
    except Exception:
        # Provider/parser exceptions must not echo rejected model text.
        raise content.AdmissionError("review-result-unavailable") from None


def admitted_review_bytes(result, metadata, subject, reviewed_lines, inventory, policy, *, now=None):
    """Return an admitted immutable proposal without a sender or credentials.

    The publisher independently authenticates its Authorization and current
    Facts and admits these same bytes at its final effect boundary. This
    preparation is neither a native proof nor publication authorization.
    """
    payload = final_review_payload(result, metadata, subject, reviewed_lines)
    try:
        content.validate_policy(policy)
        repositories = content.inventory_repositories(inventory, policy, now or datetime.now(timezone.utc))
        repository = repositories.get(subject["repository"].casefold())
        require(repository is not None and repository["id"] == subject["repository_id"]
                and repository["visibility"] == "public" and repository["archived"] is False,
                "review-public-target")
        # The callback is a pure byte return, never a publishing transport.
        return content.guarded_payload("review", subject["repository"], payload,
                                       inventory, policy, lambda wire: wire, now=now)
    except content.AdmissionError:
        raise
    except Exception:
        raise content.AdmissionError("review-admission-unavailable") from None
