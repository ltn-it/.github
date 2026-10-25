"""Read-only GitHub OIDC/native-budget issuer for a bounded review pilot.

No installed source currently admits this protocol. Registration is read only
from the externally selected active Root Required source, never candidate HEAD.
The private Ops approval metadata envelope is deliberately not an input.
"""
import base64
import http.client
import json
import re
import ssl
import time
from datetime import datetime, timezone
from dataclasses import asdict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import workflow_control as control
from collaboration_content import AdmissionError, inventory_repositories, require, validate_policy
from collaboration_inventory import organization_inventory
from collaboration_https import unique_object
from collaboration_publisher import Authorization, Facts, ROOT, ROOT_ID, digest, fixed_hash, json_bytes, positive


RULE = 25154946
REGISTRY = ".lit/collaboration-publisher-registration.json"
POLICY = ".lit/collaboration-content-policy.json"
ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "urn:ltn-it:collaboration-publisher:v1:"
MAX_TOKEN = 16384


def decode64(value):
    require(type(value) is str and 0 < len(value) <= MAX_TOKEN
            and re.fullmatch(r"[A-Za-z0-9_-]+", value), "issuer-encoding")
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(base64.urlsafe_b64encode(data).rstrip(b"=").decode() == value, "issuer-encoding")
    return data


def document(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def numeric(value):
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value), "issuer-numeric-claim")
    return int(value)


def signing_keys():
    """One fixed, verified TLS GET; no redirects, proxies, token or retries."""
    connection = http.client.HTTPSConnection("token.actions.githubusercontent.com", timeout=15,
                                            context=ssl.create_default_context())
    try:
        connection.request("GET", "/.well-known/jwks", headers={"Accept": "application/json"})
        response = connection.getresponse()
        require(response.status == 200, "issuer-keys-unavailable")
        raw = response.read(262145)
        require(len(raw) <= 262144, "issuer-keys-size")
        return document(raw)
    finally:
        connection.close()


def authenticate(token, keys, *, audience, registration, now):
    """Verify the actual RS256 signature before accepting job identity claims."""
    require(type(token) is str and 0 < len(token) <= MAX_TOKEN and token.count(".") == 2,
            "issuer-token-shape")
    header64, claims64, signature64 = token.split(".")
    header, claims = document(decode64(header64)), document(decode64(claims64))
    require(type(header) is dict and set(header) <= {"alg", "typ", "kid", "x5t"}
            and header.get("typ") == "JWT" and header.get("alg") == "RS256"
            and type(header.get("kid")) is str and 0 < len(header["kid"]) <= 256,
            "issuer-token-header")
    require(type(keys) is dict and type(keys.get("keys")) is list
            and 0 < len(keys["keys"]) <= 32, "issuer-keys-shape")
    matches = [key for key in keys["keys"] if type(key) is dict and key.get("kid") == header["kid"]]
    require(len(matches) == 1, "issuer-key-ambiguous")
    key = matches[0]
    require(key.get("kty") == "RSA" and key.get("use") == "sig" and key.get("alg") == "RS256",
            "issuer-key-type")
    modulus, exponent = int.from_bytes(decode64(key["n"]), "big"), int.from_bytes(decode64(key["e"]), "big")
    require(2048 <= modulus.bit_length() <= 4096 and exponent == 65537, "issuer-key-bounds")
    rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(
        decode64(signature64), (header64 + "." + claims64).encode(), padding.PKCS1v15(), hashes.SHA256())
    require(type(claims) is dict and claims.get("iss") == ISSUER and claims.get("aud") == audience
            and claims.get("sub") == registration["subject"], "issuer-token-subject")
    require(all(type(claims.get(field)) is int for field in ("iat", "nbf", "exp"))
            and claims["iat"] <= claims["nbf"] <= now < claims["exp"]
            and 0 < claims["exp"] - claims["iat"] <= 600, "issuer-token-time")
    require(type(claims.get("jti")) is str and 0 < len(claims["jti"]) <= 256,
            "issuer-token-identity")
    require(claims.get("repository") == ROOT and numeric(claims.get("repository_id")) == ROOT_ID
            and claims.get("repository_owner") == "ltn-it"
            and numeric(claims.get("repository_owner_id")) == control.ORGANIZATION_ID
            and claims.get("repository_visibility") == "public"
            and claims.get("event_name") == "pull_request"
            and claims.get("workflow_ref") == registration["workflow_ref"]
            and claims.get("workflow_sha") == registration["source_sha"], "issuer-token-origin")
    for field in ("run_id", "run_attempt", "check_run_id"):
        numeric(claims.get(field))
    return claims


def registration(api):
    """Root Main's real active Required source is the sole registration locator."""
    rule = api.call(f"orgs/ltn-it/rulesets/{RULE}")
    require(rule.get("id") == RULE and rule.get("enforcement") == "active"
            and rule.get("target") == "branch"
            and rule.get("conditions") == {"repository_id": {"repository_ids": [ROOT_ID]},
                                          "ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "issuer-source-scope")
    rules = [r for r in rule.get("rules", []) if r.get("type") == "workflows"]
    require(len(rules) == 1, "issuer-source-selection")
    workflows = rules[0].get("parameters", {}).get("workflows")
    require(type(workflows) is list and len(workflows) == 1, "issuer-source-selection")
    source = workflows[0]
    require(source.get("repository_id") == ROOT_ID and source.get("path") == control.WORKFLOW
            and source.get("ref") == "refs/heads/main" and fixed_hash(source.get("sha"), 40),
            "issuer-source-selection")
    value = document(api.file(ROOT, REGISTRY, source["sha"]))
    require(type(value) is dict and set(value) == {"version", "repository_id", "principal_kind",
            "origin_producer_id", "publisher_actor_id", "subject", "workflow_ref", "operation", "job"}
            and type(value["version"]) is int and value["version"] == 1
            and value["repository_id"] == ROOT_ID
            and value["principal_kind"] == "github-actions-job"
            and positive(value["origin_producer_id"]) and positive(value["publisher_actor_id"])
            and type(value["subject"]) is str and 0 < len(value["subject"]) <= 1024
            and value["workflow_ref"] == f"{ROOT}/{control.WORKFLOW}@refs/heads/main"
            and value["operation"] == "review.create" and value["job"] == "Protected current revision",
            "issuer-registration")
    # The file cannot contain its own Git commit hash. Only the independent
    # selected source supplies this value after the immutable file read.
    value["source_sha"] = source["sha"]
    return value


class NativeReviewIssuer:
    """One review.create per authenticated Required run/attempt/job/PR.

    The api is the trusted broker's authenticated read-only GitHub client, not
    producer data. No provider request, budget allocation, retry or live grant
    is created. The old already-consumed native Codex reservation is required.
    Publisher/PrivateLedger remain responsible for one-effect consumption.
    """

    def __init__(self, api, token, number, wire, policy, inventory, *, clock=time.time, keys=signing_keys):
        self.api, self.token, self.number, self.wire = api, token, number, wire
        self.inventory = document(json_bytes(inventory))
        self.policy_hash, self.inventory_hash = digest(json_bytes(policy)), digest(json_bytes(inventory))
        require(positive(number) and type(wire) is bytes, "issuer-request")
        self.payload_hash = digest(wire)
        self.audience = AUDIENCE + digest(json_bytes({"operation": "review.create", "pull": number,
            "payload": self.payload_hash, "policy": self.policy_hash, "inventory": self.inventory_hash}))
        self.clock, self.keys = clock, keys

    def issue(self):
        return self._authenticated()[0]

    def evidence(self, authorization):
        observed, evidence = self._authenticated()
        require(type(authorization) is Authorization and observed == authorization, "issuer-evidence-drift")
        return evidence

    def _authenticated(self):
        try:
            return self._issue()
        except Exception:
            raise AdmissionError("issuer-not-admitted-or-stale") from None

    def _issue(self):
        api = self.api
        admitted = registration(api)
        claims = authenticate(self.token, self.keys(), audience=self.audience, registration=admitted, now=self.clock())
        accepted_policy = document(api.file(ROOT, POLICY, admitted["source_sha"]))
        validate_policy(accepted_policy)
        require(digest(json_bytes(accepted_policy)) == self.policy_hash, "issuer-policy")
        inventory_repositories(self.inventory, accepted_policy, datetime.fromtimestamp(self.clock(), timezone.utc))
        class Reader:
            get = staticmethod(api.call)
        current_inventory = organization_inventory(Reader())
        require(current_inventory["repositories"] == self.inventory["repositories"], "issuer-inventory")
        require(control.current_repository(api, ROOT) == ROOT_ID, "issuer-repository")
        repository = api.call(f"repos/{ROOT}")
        require(repository.get("visibility") == "public" and repository.get("private") is False,
                "issuer-visibility")
        pull = control.live_pull(api, ROOT, self.number)
        require(pull["base"]["ref"] == "develop" and (pull["head"].get("repo") or {}).get("id") == ROOT_ID,
                "issuer-pilot-target")
        run_id, attempt, job_id = (numeric(claims[field]) for field in ("run_id", "run_attempt", "check_run_id"))
        run = api.call(f"repos/{ROOT}/actions/runs/{run_id}")
        require(type(run.get("id")) is int and run["id"] == run_id
                and type(run.get("run_attempt")) is int and run["run_attempt"] == attempt and attempt <= 100
                and control.native_required(run, ROOT) and run.get("status") == "in_progress"
                and "conclusion" in run and run["conclusion"] is None and run.get("head_sha") == pull["head"]["sha"]
                and (run.get("repository") or {}).get("id") == ROOT_ID, "issuer-native-run")
        bindings = {}
        runs = api.pages(f"repos/{ROOT}/actions/runs?head_sha={pull['head']['sha']}", "workflow_runs")
        require(len(runs) <= 100, "issuer-history-bound")
        candidates = control.ingress_candidates(api, ROOT, pull, [admitted["source_sha"]], runs, bindings)
        require(candidates and candidates[0]["id"] == run_id and candidates[0]["run_attempt"] == attempt,
                "issuer-native-generation")
        operation = control.operation_record(api, ROOT, run, admitted["source_sha"])
        require(operation.get("binding") == control.binding(pull), "issuer-native-operation")
        jobs = control.native_jobs(api, ROOT, run)
        selected = [j for j in jobs if j.get("id") == job_id and j.get("name") == admitted["job"]]
        require(len(selected) == 1 and type(selected[0].get("run_attempt")) is int
                and selected[0]["run_attempt"] == attempt
                and selected[0].get("head_sha") == run["head_sha"]
                and selected[0].get("check_run_url") == f"https://api.github.com/repos/{ROOT}/check-runs/{job_id}"
                and selected[0].get("status") == "in_progress"
                and "conclusion" in selected[0] and selected[0]["conclusion"] is None,
                "issuer-native-job")
        funded = [step for step in selected[0].get("steps", []) if step.get("name") == "Reserve protected Codex request"]
        require(len(funded) == 1 and funded[0].get("status") == "completed"
                and funded[0].get("conclusion") == "success", "issuer-native-budget")
        for name in ("Protected exact-revision Codex review", "Collect and verify the protected model receipt"):
            captured = [step for step in selected[0].get("steps", []) if step.get("name") == name]
            require(len(captured) == 1 and captured[0].get("status") == "completed"
                    and captured[0].get("conclusion") == "success", "issuer-native-capture")
        control.slot_consumed_before(api, ROOT, run, attempt)
        require(control.request_slot_started(api, ROOT, run) is True, "issuer-native-budget")
        # This is a proof of the already-used slot, never a new provider grant.
        for previous in runs:
            if previous["id"] == run_id or not control.native_required(previous, ROOT):
                continue
            associated = [p for p in previous.get("pull_requests", []) if p.get("number") == self.number
                          and p.get("base", {}).get("sha") == pull["base"]["sha"]
                          and p.get("head", {}).get("sha") == pull["head"]["sha"]]
            if not associated:
                continue
            require(type(previous.get("run_attempt")) is int and 1 <= previous["run_attempt"] <= 100,
                    "issuer-budget-history")
            for version in range(1, previous["run_attempt"] + 1):
                require(control.request_slot_started(api, ROOT, previous, attempt=version) is not True,
                        "issuer-budget-already-consumed")
        require(registration(api) == admitted, "issuer-registration-drift")
        control.live_pull(api, ROOT, self.number, control.binding(pull))
        current = api.call(f"repos/{ROOT}")
        require(current.get("id") == ROOT_ID and current.get("full_name") == ROOT
                and current.get("visibility") == "public" and current.get("private") is False
                and current.get("archived") is False and current.get("disabled") is False,
                "issuer-final-target")
        # The existing common reader's final I/O is the latest generation list.
        # No registration/artifact/approval read may follow it.
        control.revalidate_native_generation(api, ROOT, pull, [admitted["source_sha"]], run, bindings)
        require(self.clock() < claims["exp"], "issuer-token-expired-during-read")
        generation = digest(json_bytes({"run": run_id, "attempt": attempt, "job": job_id,
            "binding": control.binding(pull), "registration": admitted, "operation": control.digest(operation)}))
        facts = Facts(ROOT, ROOT_ID, "public", admitted["origin_producer_id"], admitted["source_sha"],
                      admitted["publisher_actor_id"], pull["head"]["sha"], generation)
        # Payload/JTI are deliberately NOT operation-ID inputs: changing bytes
        # or asking GitHub for another token cannot allocate another write slot.
        operation_id = digest(json_bytes({"protocol": "native-review-publisher/v1", "repository": ROOT_ID,
            "run": run_id, "attempt": attempt, "job": job_id, "pull": self.number, "operation": "review.create"}))
        auth = Authorization(operation_id, "review.create", self.number, None, "pull", self.payload_hash,
                             self.policy_hash, self.inventory_hash, facts)
        evidence = {"repository_id": ROOT_ID, "origin_producer_id": facts.origin_producer_id,
                    "publisher_actor_id": facts.publisher_actor_id, "origin_source": facts.origin_source,
                    "head_sha": facts.head_sha, "generation": generation, "run_id": run_id,
                    "run_attempt": attempt, "job_id": job_id, "authorization_sha256": digest(json_bytes(asdict(auth))),
                    "native_evidence_sha256": generation, "before_fields": {}, "provider_response_sha256": None}
        return auth, evidence

    def attest(self, authorization):
        require(type(authorization) is Authorization and self.issue() == authorization, "issuer-authorization-drift")
        return authorization.facts
