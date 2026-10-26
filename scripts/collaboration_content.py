"""Bounded offline content admission. No network, deletion, or history effects.

The trusted caller supplies a freshly completed authoritative inventory. This
module is not an authenticity check for an inventory supplied by a contributor.
No exception, result, or diagnostic includes matched input values.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


# Includes stateless installation tokens with numeric IDs and base64url/dot
# segments, also accepted by the fixed HTTPS transport. Detection is deliberately
# not a credential-validity check. No match is ever returned in diagnostics.
GITHUB_TOKEN_PATTERN = r"(?:gh[pousr]_[a-z0-9_.-]{20,}|github_pat_[a-z0-9_]{20,})"


class AdmissionError(Exception):
    """Only fixed safe categories may cross the reporting boundary."""


def require(condition, category):
    if not condition:
        raise AdmissionError(category)


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def timestamp(value):
    require(type(value) is str and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value)),
            "inventory-time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise AdmissionError("inventory-time") from None


def policy_from(path):
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise AdmissionError("policy-unavailable") from None
    validate_policy(policy)
    return policy


def validate_policy(policy):
    require(type(policy) is dict and set(policy) == {
        "version", "max_text_bytes", "inventory_max_age_seconds", "owner",
        "approved_public_urls", "approved_public_identifiers", "protected_value_sha256"}, "policy-shape")
    require(policy["version"] == 1 and type(policy["max_text_bytes"]) is int
            and 1 <= policy["max_text_bytes"] <= 262144
            and type(policy["inventory_max_age_seconds"]) is int
            and 1 <= policy["inventory_max_age_seconds"] <= 900
            and policy["owner"] == "litroc", "policy-bounds")
    for name in ("approved_public_urls", "approved_public_identifiers", "protected_value_sha256"):
        values = policy[name]
        require(type(values) is list and all(type(v) is str and v for v in values)
                and len(set(values)) == len(values), "policy-list")
    require(all(re.fullmatch(r"[0-9a-f]{64}", v) for v in policy["protected_value_sha256"]), "policy-hash")
    for value in policy["approved_public_urls"]:
        try:
            url = strict_https_destination(value)
            require(not url.query and not url.fragment and not private_host(url.hostname), "policy-public-source")
        except AdmissionError:
            raise AdmissionError("policy-public-source") from None



def inventory_repositories(inventory, policy, now):
    require(type(inventory) is dict and set(inventory) == {
        "version", "organization", "started_at", "finished_at", "complete", "repositories"}, "inventory-shape")
    require(inventory["version"] == 1 and inventory["organization"] == "ltn-it"
            and inventory["complete"] is True, "inventory-incomplete")
    start, finish = timestamp(inventory["started_at"]), timestamp(inventory["finished_at"])
    require(start <= finish <= now and (now - start).total_seconds() <= policy["inventory_max_age_seconds"],
            "inventory-stale")
    rows = inventory["repositories"]
    require(type(rows) is list and 0 < len(rows) <= 10000, "inventory-repositories")
    names, ids = {}, set()
    for row in rows:
        require(type(row) is dict and set(row) == {"id", "full_name", "visibility", "archived"}, "inventory-row")
        require(type(row["id"]) is int and row["id"] > 0 and row["id"] not in ids
                and type(row["full_name"]) is str
                and re.fullmatch(r"ltn-it/[A-Za-z0-9_.-]+", row["full_name"])
                and row["full_name"].casefold() not in names
                and row["visibility"] in ("public", "private", "internal")
                and type(row["archived"]) is bool, "inventory-row")
        names[row["full_name"].casefold()] = row
        ids.add(row["id"])
    return names


def private_host(host):
    host = host.casefold().rstrip(".")
    if host == "localhost" or host.endswith((".atlassian.net", ".internal", ".local", ".corp", ".lan")):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def normalized(value, maximum):
    require(type(value) is str, "content-type")
    try:
        require(len(value.encode("utf-8")) <= maximum, "content-size")
    except UnicodeError:
        raise AdmissionError("content-encoding") from None
    require(not any(unicodedata.category(c) in ("Cf", "Cs") or (ord(c) < 32 and c not in "\n\r\t")
                    for c in value), "content-control-character")
    value = unicodedata.normalize("NFKC", value)
    for _ in range(4):
        expanded = unicodedata.normalize("NFKC", html.unescape(unquote(value)))
        if expanded == value:
            return value
        value = expanded
    require(unicodedata.normalize("NFKC", html.unescape(unquote(value))) == value, "content-encoding-depth")
    return value


def public_github_route(parts):
    """Repository visibility alone cannot admit settings or draft resources."""
    if not parts:
        return True
    family = parts[0]
    if len(parts) == 1:
        return family in {"issues", "pulls", "discussions", "releases", "tags", "wiki"}
    if family in {"issues", "pull", "discussions"}:
        numbered = bool(re.fullmatch(r"[1-9][0-9]*", parts[1]))
        return numbered and (len(parts) == 2 or
                             (family == "pull" and len(parts) == 3
                              and parts[2] in {"files", "commits", "checks"}))
    if family == "commit":
        return len(parts) == 2 and bool(re.fullmatch(r"[0-9a-fA-F]{40}", parts[1]))
    if family in {"blob", "tree"}:
        return len(parts) >= 3
    if family in {"wiki", "compare"}:
        return True
    if parts == ["security", "policy"]:
        return True
    if parts[:2] == ["actions", "runs"]:
        return (len(parts) in (3, 5) and bool(re.fullmatch(r"[1-9][0-9]*", parts[2]))
                and (len(parts) == 3 or (parts[3] in {"job", "attempts"}
                                         and bool(re.fullmatch(r"[1-9][0-9]*", parts[4])))))
    return False


def strict_https_destination(target):
    """Parse only canonical transport syntax, before any URL allowlist checks.

    Browsers remove ASCII whitespace and treat backslashes as path separators;
    urlsplit does not implement that model. Reject these representations rather
    than validating a different destination. Non-ASCII URL spelling is likewise
    unsupported here; callers must supply an explicitly reviewed ASCII URL.
    """
    require(bool(target) and target.isascii()
            and not any(c.isspace() or unicodedata.category(c) == "Cc" for c in target)
            and "\\" not in target, "unsupported-link-destination")
    try:
        url = urlsplit(target)
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and url.port is None, "unapproved-url")
        return url
    except ValueError:
        raise AdmissionError("malformed-url") from None


class HTMLDestinations(HTMLParser):
    """Retain entire parsed attribute values, including internal whitespace."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.destinations = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in {"href", "src"}:
                self.destinations.append(value or "")


def link_destinations(value):
    """Extract candidates only; every representation uses the same validator.

    Explicit destinations are never stripped or repaired. Punctuation removal
    applies only to prose autolink candidates, preserving the previous public
    technical-text contract. Bare www autolinks are recognized but unsupported.
    """
    parser = HTMLDestinations()
    parser.feed(value)
    parser.close()
    targets = set(parser.destinations)
    for pattern in (r"\]\(\s*(?:<([^>]*)>|([^\s)]+))",
                    r"(?m)^[ \t]{0,3}\[[^\n]+\]:[ \t]*(?:<([^>]*)>|([^\s]+))"):
        for match in re.finditer(pattern, value):
            targets.add(next(group for group in match.groups() if group is not None))
    for match in re.finditer(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>\"'`]+", value):
        targets.add(match.group().rstrip(".,;:!?)\]}"))
    return targets


def destination_categories(target, policy, repositories):
    """One fail-closed destination policy for HTML, Markdown and autolinks."""
    if re.fullmatch(r"#[A-Za-z0-9_.:-]+", target):
        return []
    try:
        url = strict_https_destination(target)
    except AdmissionError as error:
        return [str(error)]
    if private_host(url.hostname):
        return ["private-system"]
    if url.hostname.casefold() == "github.com":
        parts = url.path.strip("/").split("/")
        name = "/".join(parts[:2]).casefold()
        if (len(parts) < 2 or any(part in ("", ".", "..") for part in parts)
                or name not in repositories or repositories[name]["visibility"] != "public"
                or not public_github_route(parts[2:]) or url.query or url.fragment):
            return ["unverified-public-source"]
    elif target not in policy["approved_public_urls"]:
        return ["unapproved-url"]
    return []


def scan_text(value, policy, repositories):
    original = value
    value = normalized(value, policy["max_text_bytes"])
    categories = set()
    if any(unicodedata.category(c) in ("Cf", "Cs") or (ord(c) < 32 and c not in "\n\r\t") for c in value):
        categories.add("content-control-character")
    if re.search(r"(?i)(?:[a-z0-9-]+\.)*atlassian\.net\b|\b[a-z0-9.-]+\.(?:internal|local|corp|lan)\b", value):
        categories.add("private-system")
    for found in re.finditer(r"\b(?:CVE-[0-9]{4}-[0-9]+|[A-Z][A-Z0-9]{1,15}-[1-9][0-9]*)\b", value, re.I):
        token = found.group().upper()
        if token not in policy["approved_public_identifiers"] and not re.fullmatch(r"(?:CVE-[0-9]{4}|CWE|RFC)-[0-9]+", token):
            categories.add("private-identifier")
    if re.search(r"(?i)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\b(?:" + GITHUB_TOKEN_PATTERN
                 + r"|AKIA[A-Z0-9]{16}|sk-[a-z0-9_-]{20,})\b", value):
        categories.add("credential")
    if re.search(r"(?i)\b(?:password|passwd|secret|token|api[_ -]?key|authorization)\s*[:=]\s*[^\s]{4,}", value):
        categories.add("secret-like")
    if re.search(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", value):
        categories.add("personal-data")
    for address in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|\[?[0-9a-fA-F]*:[0-9a-fA-F:]+\]?", value):
        try:
            if not ipaddress.ip_address(address.strip("[]")).is_global:
                categories.add("protected-infrastructure")
        except ValueError:
            pass
    # Hash-only private supplements never add raw protected infrastructure to
    # public source. Match complete lexical values; arbitrary substrings are
    # not claimed covered by this exact-value control.
    for token in re.findall(r"[^\s\"'<>`(),;]+", value):
        if sha256(token.casefold()) in policy["protected_value_sha256"]:
            categories.add("protected-value")
    # Extraction does not decide visibility or repair browser-normalized URLs.
    # All recognized forms pass the exact same strict destination boundary.
    # Retain raw HTML attribute boundaries too: decoding an entity to whitespace
    # before parsing could split a single browser destination into attributes.
    for target in link_destinations(original) | link_destinations(value):
        target = normalized(target, policy["max_text_bytes"])
        categories.update(destination_categories(target, policy, repositories))
    return sorted(categories)


def validate(publication, inventory, policy, *, now=None):
    """Inspect a final title/body envelope; return only hashes and categories.

    The caller must extract every submitted body, including inline review
    comments, and transmit the exact admitted bytes. A successful result is
    content admission only, never authorization, review, or native acceptance.
    """
    validate_policy(policy)
    repositories = inventory_repositories(inventory, policy, now or datetime.now(timezone.utc))
    require(type(publication) is dict and set(publication) == {"kind", "repository", "title", "body"}, "publication-shape")
    require(publication["kind"] in ("issue", "pull_request", "review", "comment", "review_comment"), "publication-kind")
    repository = publication["repository"]
    require(type(repository) is str and repository.casefold() in repositories, "publication-repository")
    categories = set()
    for field in ("title", "body"):
        categories.update(scan_text(publication[field], policy, repositories))
    wire = json.dumps(publication, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {"version": 1, "admitted": not categories, "categories": sorted(categories),
            "content_sha256": sha256(wire),
            "policy_sha256": sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"))),
            "inventory_sha256": sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")))}


def guarded_payload(kind, repository, payload, inventory, policy, send, *, now=None):
    """Serialize once, inspect every title/body, send those same frozen bytes.

    `send` is the existing publisher's one-effect transport, supplied by trusted
    code. No token, API client, retries, authorization or mutating implementation
    is defined here. Unknown fields fail so new surfaces require explicit wiring.
    """
    require(type(payload) is dict, "payload-shape")
    fields = {
        "issue": {"title", "body"},
        "pull_request": {"title", "body", "head", "base", "draft"},
        "comment": {"body"},
        "review_comment": {"body", "commit_id", "path", "line", "side", "start_line", "start_side", "in_reply_to"},
        "review": {"body", "commit_id", "event", "comments"},
    }
    require(kind in fields and set(payload) <= fields[kind] and ("title" in payload or "body" in payload
            or (kind == "review" and "comments" in payload)), "payload-fields")
    require("title" not in payload or (type(payload["title"]) is str and bool(payload["title"])), "payload-title")
    require("body" not in payload or payload["body"] is None or type(payload["body"]) is str, "payload-body")
    try:
        wire = json.dumps(payload, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        frozen = json.loads(wire)
    except (ValueError, TypeError, UnicodeError):
        raise AdmissionError("payload-encoding") from None
    require(len(wire) <= policy["max_text_bytes"], "payload-size")
    # Inspect all non-body strings too: branch names and inline file paths must
    # not become an alternate metadata disclosure path.
    texts = []

    def collect(value):
        if type(value) is str:
            texts.append(value)
        elif type(value) is dict:
            for key, child in value.items():
                require(type(key) is str, "payload-key")
                collect(child)
        elif type(value) is list:
            for child in value:
                collect(child)
        else:
            require(value is None or type(value) in (int, bool), "payload-value")

    if "comments" in frozen:
        require(kind == "review" and type(frozen["comments"]) is list and len(frozen["comments"]) <= 100,
                "payload-inline-comments")
        for comment in frozen["comments"]:
            require(type(comment) is dict and set(comment) <= fields["review_comment"]
                    and type(comment.get("body")) is str, "payload-inline-comment")
    collect(frozen)
    for value in texts:
        result = validate({"kind": kind, "repository": repository, "title": "", "body": value},
                          inventory, policy, now=now)
        require(result["admitted"], "publication-content-rejected")
    # Validate even an empty/null body; malformed/untrusted inventory cannot
    # skip admission merely because there are no strings.
    validate({"kind": kind, "repository": repository, "title": "", "body": ""}, inventory, policy, now=now)
    return send(wire)


def history_disposition(metadata):
    """Classify exact history locators; never infer consent or delete anything."""
    require(type(metadata) is dict and set(metadata) == {"node_id", "revision_id", "deleted_at", "diff_available"},
            "history-shape")
    require(all(type(metadata[key]) is str and re.fullmatch(r"[A-Za-z0-9_=-]{1,200}", metadata[key])
                for key in ("node_id", "revision_id")) and type(metadata["diff_available"]) is bool, "history-locator")
    if metadata["deleted_at"] is not None:
        timestamp(metadata["deleted_at"])
        require(metadata["diff_available"] is False, "history-inconsistent")
        return "deleted-revision-observed"
    return "exact-human-authorization-required"
