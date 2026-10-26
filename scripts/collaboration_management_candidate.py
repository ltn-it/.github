"""Local candidate for owned PR publication in private Management Actions.

No current selected Source admits REGISTRY, operation or journal branch. APIs
and sender are fixed trusted deployment inputs, never fields of a request.
No new host, workflow, token, grant, approval, ref or live effect is installed.
"""
import base64
import hashlib
import http.client
import re
import ssl
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import quote

import yaml

import workflow_control as control
from collaboration_content import AdmissionError, guarded_payload, inventory_repositories, require, validate_policy
from collaboration_inventory import organization_inventory
from collaboration_native_issuer import document, numeric, signing_keys, verified_claims
from collaboration_app_credential import AppTokenPreparer
from collaboration_https import HTTPSOnceSender
from collaboration_publisher import Authorization, BoundedTransport, Facts, Publisher, ROOT, ROOT_ID
from collaboration_publisher import digest, fixed_hash, json_bytes, positive, shape


MANAGEMENT = "ltn-it/github-management-lit"
MANAGEMENT_ID = 1273655215
RULE = 25219015
WORKFLOW = ".github/workflows/terraform-github-management.yml"
REGISTRY = ".lit/collaboration-owned-publisher.json"
POLICY = ".lit/collaboration-content-policy.json"
JOURNAL_BRANCH = "operation-data/collaboration-journal"
GROUP = "terraform-github-management-state"
# Preserve the actual Main expression, including its separate Root preparation
# branch; owned workflow_dispatch selects GROUP without changing those routes.
CONCURRENCY = ("${{ (inputs.operation == 'native-promotion-prepare' || inputs.operation == 'namespace-recovery-prepare') "
    "&& inputs.repository == '.github' && 'native-root-promotion-preparation' || "
    "github.event_name == 'workflow_dispatch' && 'terraform-github-management-state' || "
    "format('terraform-github-management-validation-{0}', github.ref) }}")
AUDIENCE = "urn:ltn-it:owned-collaboration:v1:"
MAXIMUM = 262144


def selected_registration(api):
    rule = api.call(f"orgs/ltn-it/rulesets/{RULE}")
    require(rule.get("id") == RULE and rule.get("enforcement") == "active"
            and rule.get("target") == "branch"
            and rule.get("conditions") == {"repository_id": {"repository_ids": [MANAGEMENT_ID]},
                "ref_name": {"include": ["refs/heads/develop", "refs/heads/main"], "exclude": []}},
            "owned-selection-scope")
    choices = [r for r in rule.get("rules", []) if r.get("type") == "workflows"]
    require(len(choices) == 1, "owned-selection")
    sources = choices[0].get("parameters", {}).get("workflows")
    require(type(sources) is list and len(sources) == 1, "owned-selection")
    source = sources[0]
    require(source.get("repository_id") == ROOT_ID and source.get("path") == control.WORKFLOW
            and source.get("ref") == "refs/heads/main" and fixed_hash(source.get("sha"), 40),
            "owned-selection")
    entry = document(api.file(ROOT, REGISTRY, source["sha"]))
    require(type(entry) is dict and set(entry) == {"version", "management_main", "subject", "job",
            "origin_producer_id", "publisher_actor_id", "role", "operation", "journal_branch", "journal_rule_id"}
            and type(entry["version"]) is int and entry["version"] == 1
            and fixed_hash(entry["management_main"], 40)
            and type(entry["subject"]) is str and entry["subject"]
            and entry["job"] == "Publish checked collaboration"
            and positive(entry["origin_producer_id"]) and positive(entry["publisher_actor_id"])
            and entry["role"] in {"owned-sync", "owned-release"}
            and entry["operation"] == "pull.create" and entry["journal_branch"] == JOURNAL_BRANCH
            and positive(entry["journal_rule_id"]),
            "owned-registration")
    workflow = yaml.safe_load(api.file(MANAGEMENT, WORKFLOW, entry["management_main"]))
    require(workflow.get("concurrency") == {"group": CONCURRENCY, "cancel-in-progress": False},
            "owned-single-writer-definition")
    job = workflow.get("jobs", {}).get("collaboration-publish", {})
    require(job.get("name") == entry["job"] and job.get("permissions") ==
            {"contents": "write", "actions": "read", "id-token": "write"},
            "owned-job-definition")
    return entry, source["sha"]


def private_repository(api):
    repo = api.call(f"repos/{MANAGEMENT}")
    require(repo.get("id") == MANAGEMENT_ID and repo.get("full_name") == MANAGEMENT
            and repo.get("visibility") == "private" and repo.get("private") is True
            and repo.get("archived") is False and repo.get("disabled") is False,
            "owned-private-repository")


def native_manifest(api, run, *, artifact_credential=None):
    # Explicit private job credential only: the parent may also hold App, Jira
    # and OIDC credentials. None of its environment/config reaches gh.
    require(type(artifact_credential) is str and 0 < len(artifact_credential) <= 16384
            and all(33 <= ord(c) <= 126 for c in artifact_credential), "owned-artifact-credential")
    require(type(run) is dict and positive(run.get("id")) and run.get("run_attempt") == 1,
            "owned-private-manifest")
    name = "collaboration-owned-operation-1"
    records = api.pages(f"repos/{MANAGEMENT}/actions/runs/{run['id']}/artifacts", "artifacts")
    matches = [r for r in records if r.get("name") == name and r.get("expired") is False]
    require(len(matches) == 1 and positive(matches[0].get("size_in_bytes"))
            and matches[0]["size_in_bytes"] <= MAXIMUM, "owned-private-manifest")
    with tempfile.TemporaryDirectory(prefix="owned-publication-") as temporary:
        root = Path(temporary)
        home, config, directory = (root / part for part in ("home", "config", "artifact"))
        for child in (home, config, directory):
            child.mkdir(mode=0o700)
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
                       "GH_CONFIG_DIR": str(config), "XDG_CONFIG_HOME": str(config),
                       "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1",
                       "GH_TOKEN": artifact_credential}
        try:
            completed = subprocess.run(["/usr/local/bin/gh", "run", "download", str(run["id"]),
                                       "--repo", MANAGEMENT, "--name", name, "--dir", str(directory)],
                                      env=environment, cwd=home, stdin=subprocess.DEVNULL,
                                      capture_output=True, timeout=60, check=False)
        except (OSError, subprocess.SubprocessError):
            raise AdmissionError("owned-private-manifest") from None
        require(completed.returncode == 0, "owned-private-manifest")
        path = directory / "operation.json"
        require(list(directory.iterdir()) == [path] and path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= MAXIMUM, "owned-private-manifest")
        wire = path.read_bytes()
        value = document(wire)
        require(json_bytes(value) == wire, "owned-private-manifest")
        return value


class OwnedIssuer:
    """Authenticates a future selected private principal, not an old approval.

    This owned deterministic PR path allocates no AI budget and makes no review
    proof. Registration, job and operation artifact are absent in current Main.
    """
    def __init__(self, api, token, wire, policy, inventory, *, clock=time.time, keys=signing_keys,
                 artifact_credential=None):
        self.api, self.token, self.wire = api, token, wire
        self.policy, self.inventory = document(json_bytes(policy)), document(json_bytes(inventory))
        self.clock, self.keys = clock, keys
        self.artifact_credential = artifact_credential
        self.audience = AUDIENCE + digest(wire)

    def issue(self):
        try:
            return self._issue()
        except Exception:
            raise AdmissionError("owned-not-admitted-or-stale") from None

    def _issue(self):
        api = self.api
        registration, source = selected_registration(api)
        claims = verified_claims(self.token, self.keys(), audience=self.audience,
                                 subject=registration["subject"], now=self.clock())
        require(claims.get("repository") == MANAGEMENT
                and numeric(claims.get("repository_id")) == MANAGEMENT_ID
                and claims.get("repository_owner") == "ltn-it"
                and numeric(claims.get("repository_owner_id")) == control.ORGANIZATION_ID
                and claims.get("repository_visibility") == "private"
                and claims.get("event_name") == "workflow_dispatch"
                and claims.get("ref") == "refs/heads/main"
                and claims.get("sha") == registration["management_main"]
                and claims.get("workflow_sha") == registration["management_main"]
                and claims.get("workflow_ref") == f"{MANAGEMENT}/{WORKFLOW}@refs/heads/main",
                "owned-private-principal")
        run_id, attempt, job_id = (numeric(claims.get(k)) for k in ("run_id", "run_attempt", "check_run_id"))
        require(attempt == 1, "owned-no-attempt-replay")
        private_repository(api)
        require(api.call(f"repos/{MANAGEMENT}/git/ref/heads/main").get("object", {}).get("sha")
                == registration["management_main"], "owned-main-drift")
        run = api.call(f"repos/{MANAGEMENT}/actions/runs/{run_id}")
        require(run.get("id") == run_id and run.get("run_attempt") == 1
                and run.get("head_sha") == registration["management_main"] and run.get("head_branch") == "main"
                and run.get("event") == "workflow_dispatch" and run.get("path") == WORKFLOW
                and run.get("repository", {}).get("id") == MANAGEMENT_ID
                and run.get("status") == "in_progress" and "conclusion" in run and run["conclusion"] is None,
                "owned-native-run")
        jobs = api.pages(f"repos/{MANAGEMENT}/actions/runs/{run_id}/attempts/1/jobs", "jobs")
        selected = [j for j in jobs if j.get("id") == job_id and j.get("name") == registration["job"]]
        require(len(selected) == 1 and selected[0].get("run_id") == run_id
                and selected[0].get("run_attempt") == 1 and selected[0].get("head_sha") == run["head_sha"]
                and selected[0].get("status") == "in_progress"
                and "conclusion" in selected[0] and selected[0]["conclusion"] is None,
                "owned-native-job")
        prepared = [s for s in selected[0].get("steps", []) if s.get("name") == "Prepare exact owned publication"]
        require(len(prepared) == 1 and prepared[0].get("status") == "completed"
                and prepared[0].get("conclusion") == "success", "owned-native-preparation")
        manifest = native_manifest(api, run, artifact_credential=self.artifact_credential)
        require(type(manifest) is dict and set(manifest) == {"version", "role", "operation", "repository_id",
                "run_id", "run_attempt", "job_id", "base_ref", "head_ref", "base_sha", "head_sha", "payload_sha256"}
                and type(manifest["version"]) is int and manifest["version"] == 1
                and manifest["role"] == registration["role"] and manifest["operation"] == "pull.create"
                and manifest["repository_id"] == ROOT_ID and manifest["run_id"] == run_id
                and manifest["run_attempt"] == 1 and manifest["job_id"] == job_id
                and manifest["base_ref"] == "develop" and fixed_hash(manifest["base_sha"], 40)
                and fixed_hash(manifest["head_sha"], 40) and manifest["payload_sha256"] == digest(self.wire),
                "owned-native-operation")
        payload = document(self.wire)
        require(json_bytes(payload) == self.wire and payload.get("head") == manifest["head_ref"]
                and payload.get("base") == manifest["base_ref"], "owned-final-payload")
        accepted = document(api.file(ROOT, POLICY, source))
        validate_policy(accepted)
        require(accepted == self.policy, "owned-policy-drift")
        inventory_repositories(self.inventory, accepted, datetime.fromtimestamp(self.clock(), timezone.utc))
        class Reader:
            get = staticmethod(api.call)
        require(organization_inventory(Reader())["repositories"] == self.inventory["repositories"],
                "owned-inventory-drift")
        # Provisional facts permit only the existing fixed Root pull.create shape.
        identity = {k: manifest[k] for k in ("repository_id", "operation", "base_ref", "head_ref", "base_sha", "head_sha")}
        operation_id = digest(json_bytes(identity))  # no payload, token, run, source or role can buy a new slot
        generation = digest(json_bytes({"registration": registration, "source": source, "manifest": manifest}))
        facts = Facts(ROOT, ROOT_ID, "public", registration["origin_producer_id"],
                      registration["management_main"], registration["publisher_actor_id"], manifest["head_sha"], generation)
        auth = Authorization(operation_id, "pull.create", None, None, "pull", digest(self.wire),
                             digest(json_bytes(accepted)), digest(json_bytes(self.inventory)), facts)
        shape(auth, payload)
        require(guarded_payload("pull_request", ROOT, payload, self.inventory, accepted,
                               lambda wire: wire, now=datetime.fromtimestamp(self.clock(), timezone.utc)) == self.wire,
                "owned-final-payload")
        history = api.pages(f"repos/{ROOT}/pulls?state=all&head=ltn-it:{quote(manifest['head_ref'], safe='')}&base=develop&per_page=100")
        require(not any(p.get("head", {}).get("sha") == manifest["head_sha"] for p in history),
                "owned-previous-operation")
        require(selected_registration(api) == (registration, source), "owned-registration-drift")
        private_repository(api)
        require(api.call(f"repos/{MANAGEMENT}/git/ref/heads/main").get("object", {}).get("sha")
                == registration["management_main"], "owned-main-drift")
        final_run = api.call(f"repos/{MANAGEMENT}/actions/runs/{run_id}")
        require(final_run == run, "owned-native-generation-drift")
        target = api.call(f"repos/{ROOT}")
        require(target.get("id") == ROOT_ID and target.get("full_name") == ROOT
                and target.get("visibility") == "public" and target.get("private") is False
                and target.get("archived") is False and target.get("disabled") is False, "owned-target")
        for key in ("base", "head"):
            ref = api.call(f"repos/{ROOT}/git/ref/heads/{quote(manifest[key + '_ref'], safe='/')}")
            require(ref.get("object", {}).get("sha") == manifest[key + "_sha"], "owned-target-ref-drift")
        latest_jobs = api.pages(f"repos/{MANAGEMENT}/actions/runs/{run_id}/attempts/1/jobs", "jobs")
        latest = [j for j in latest_jobs if j.get("id") == job_id and j.get("name") == registration["job"]]
        require(len(latest) == 1 and latest[0].get("run_id") == run_id
                and latest[0].get("run_attempt") == 1 and latest[0].get("head_sha") == run["head_sha"]
                and latest[0].get("status") == "in_progress" and "conclusion" in latest[0]
                and latest[0]["conclusion"] is None, "owned-final-native-job")
        require(self.clock() < claims["exp"], "owned-token-expired")
        return auth

    def attest(self, auth):
        require(type(auth) is Authorization and self.issue() == auth, "owned-authorization-drift")
        return auth.facts


class PrivateJournalClient:
    """Fixed create-only HTTPS endpoint; no key lookup, redirects or retry.

    read_api and credential belong to the trusted private job. Its credential
    must independently be admitted/narrowed to Management contents only. This
    endpoint allowlist is not a claim about GitHub permission-bucket granularity.
    """
    def __init__(self, read_api, credential):
        require(callable(credential), "owned-journal-credential")
        self.call, self.file, self.pages = read_api.call, read_api.file, read_api.pages
        self._credential = credential

    def put_once(self, path, value):
        require(type(path) is str and re.fullmatch(r"repos/ltn-it/github-management-lit/contents/"
                r"\.lit/collaboration-journal/[0-9a-f]{64}/(?:intent|response)\.json", path),
                "owned-journal-endpoint")
        require(type(value) is dict and set(value) == {"message", "content", "branch"}
                and value["branch"] == JOURNAL_BRANCH and type(value["message"]) is str
                and type(value["content"]) is str, "owned-journal-create-only")
        wire = json_bytes(value)
        require(0 < len(wire) <= MAXIMUM, "owned-journal-size")
        connection = None
        try:
            token = self._credential()
            require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_.-]{20,8192}", token),
                    "owned-journal-credential")
            connection = http.client.HTTPSConnection("api.github.com", timeout=15,
                                                    context=ssl.create_default_context())
            connection.request("PUT", "/" + path, body=wire, headers={"Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                "Content-Length": str(len(wire)), "User-Agent": "ltn-it-private-publication-journal"})
            response = connection.getresponse()
            require(response.status == 201, "owned-journal-create-unknown")
            raw = response.read(MAXIMUM + 1)
            require(len(raw) <= MAXIMUM, "owned-journal-response-size")
            result = document(raw)
            require(type(result) is dict, "owned-journal-response")
            return response.status, result
        except Exception:
            raise AdmissionError("owned-journal-create-unknown") from None
        finally:
            if connection is not None:
                connection.close()


class PrivateActionsJournal:
    """Create-only private Git Contents records, never an artifact lock.

    The journal branch must already exist under a separately approved protected
    contract. No branch creation, SHA replacement, delete or retry is exposed.
    GitHub rejects create-without-SHA on an existing path. Native Main's fixed
    single-writer group supplies serialization; this class does not fabricate it.
    Unknown create outcomes burn the attempt and cannot authorize publication.
    """
    def __init__(self, api, issuer, authorization):
        self.api, self.issuer, self.authorization = api, issuer, authorization

    @contextmanager
    def serialize(self):
        self.issuer.attest(self.authorization)
        yield

    def _create(self, operation_id, phase, value):
        require(fixed_hash(operation_id) and phase in {"intent", "response"}, "owned-journal-path")
        private_repository(self.api)
        branch = self.api.call(f"repos/{MANAGEMENT}/git/ref/heads/{JOURNAL_BRANCH}")
        parent = branch.get("object", {}).get("sha")
        require(fixed_hash(parent, 40), "owned-journal-not-installed")
        registration, _ = selected_registration(self.issuer.api)
        require(registration["management_main"] == self.authorization.facts.origin_source
                and registration["publisher_actor_id"] == self.authorization.facts.publisher_actor_id,
                "owned-journal-source-drift")
        # A branch-rule projection omits bypass details and is not authority.
        rule = self.api.call(f"repos/{MANAGEMENT}/rulesets/{registration['journal_rule_id']}")
        require(rule.get("id") == registration["journal_rule_id"] and rule.get("target") == "branch"
                and rule.get("source_type") == "Repository" and rule.get("source") == MANAGEMENT
                and rule.get("enforcement") == "active" and rule.get("bypass_actors") == []
                and rule.get("conditions") == {"ref_name": {
                    "include": [f"refs/heads/{JOURNAL_BRANCH}"], "exclude": []}}
                and rule.get("rules") == [{"type": "deletion"}, {"type": "non_fast_forward"}],
                "owned-journal-ref-protection")
        wire = json_bytes(value)
        blob = hashlib.sha1(b"blob " + str(len(wire)).encode() + b"\0" + wire, usedforsecurity=False).hexdigest()
        path = f".lit/collaboration-journal/{operation_id}/{phase}.json"
        history = self.api.pages(f"repos/{MANAGEMENT}/commits?sha={quote(JOURNAL_BRANCH, safe='')}"
                                 f"&path={quote(path, safe='')}&per_page=100")
        # A deleted record is still consumed. Missing current file alone never
        # proves a first operation; normal protected ancestry preserves history.
        require(type(history) is list and not history, "owned-journal-history-consumed")
        # This trusted client must return status and JSON, must disable retry,
        # and must have only its private journal credential, not public PR rights.
        status, response = self.api.put_once(f"repos/{MANAGEMENT}/contents/{path}", {
            "message": f"Record collaboration {phase} {operation_id}",
            "content": base64.b64encode(wire).decode(), "branch": JOURNAL_BRANCH})
        require(status == 201 and response.get("content", {}).get("sha") == blob
                and [p.get("sha") for p in response.get("commit", {}).get("parents", [])] == [parent],
                "owned-journal-create-unknown")
        commit = response.get("commit", {}).get("sha")
        require(fixed_hash(commit, 40) and self.api.file(MANAGEMENT, path, commit) == wire,
                "owned-journal-readback")
        return True

    def claim(self, operation_id, fingerprint):
        require(fixed_hash(fingerprint), "owned-journal-fingerprint")
        try:
            return self._create(operation_id, "intent", {"version": 1, "operation_id": operation_id,
                "fingerprint": fingerprint})
        except Exception:
            raise AdmissionError("owned-journal-consumed-or-unknown") from None

    def record(self, auth, result):
        require(auth == self.authorization and type(result) is dict
                and result.get("operation_id") == auth.operation_id
                and result.get("payload_sha256") == auth.payload_sha256,
                "owned-journal-response")
        self._create(auth.operation_id, "response", {"version": 1, "authorization_sha256":
            digest(json_bytes(auth.__dict__ | {"facts": auth.facts.__dict__})), "result": result})


def publish_owned(issuer, journal_api, transport, wire, inventory, policy, *, clock=None, authorization=None):
    """Executable local composition; deployment roles/clients are not admitted."""
    started = False
    auth = None
    try:
        require(type(transport) is BoundedTransport, "owned-fixed-transport")
        auth = issuer.issue()
        require(authorization is None or authorization == auth, "owned-prepared-subject-drift")
        journal = PrivateActionsJournal(journal_api, issuer, auth)
        def once(method, url, final):
            nonlocal started
            started = True
            return transport.send_once(auth, final)
        facts = auth.facts
        publisher = Publisher(admitted_bindings={(facts.origin_producer_id, facts.publisher_actor_id): facts.origin_source},
            attest=issuer.attest, ledger=journal, serialize=journal.serialize,
            transport=BoundedTransport(once, publisher_actor_id=facts.publisher_actor_id), clock=clock)
        result = publisher.publish(auth, wire, inventory, policy)
        journal.record(auth, result)
        return result
    except Exception:
        return {"disposition": "unknown-readback-required" if started else "blocked-before-publication"}


def prepare_and_publish_owned(issuer, journal_api, app_identity, key_source, wire, inventory, policy):
    """Real credential/sender composition; no environment lookup or live grant.

    Trusted private process construction owns read API, journal credential, App
    identity and key getter. These never come from producer payloads. A separate
    durable journal intent consumes the only token mint before its POST. The
    original authorization must remain identical after every credential read.
    """
    try:
        auth = issuer.issue()
        journal = PrivateActionsJournal(journal_api, issuer, auth)
        prepared = AppTokenPreparer(app_identity, key_source, issuer.attest, journal,
            clock=issuer.clock, operation="pull.create").prepare(auth)
        issuer.attest(auth)
        transport = BoundedTransport(HTTPSOnceSender(prepared.credential),
                                     publisher_actor_id=auth.facts.publisher_actor_id)
    except Exception:
        return {"disposition": "blocked-before-publication"}
    return publish_owned(issuer, journal_api, transport, wire, inventory, policy,
        clock=lambda: datetime.fromtimestamp(issuer.clock(), timezone.utc), authorization=auth)


def readback_owned(api, authorization, wire, original_response):
    """Observe the original PR identity, never discover success by equal text.

    Inputs belong to the trusted private runtime: the exact pre-write native
    authorization, frozen payload and original durable response journal. A REST
    PR database ID is not its repository-local number. Resolve that number only
    by the recorded original ID, then read the exact object and actor/refs/bytes.
    This read-only result grants no admission, retry, cleanup or further write.
    Unknown/lost original responses cannot be reconstructed from matching text.
    """
    try:
        auth, response = authorization, original_response
        require(type(auth) is Authorization and auth.operation == "pull.create"
                and auth.facts.repository == ROOT and auth.facts.repository_id == ROOT_ID
                and type(wire) is bytes and digest(wire) == auth.payload_sha256
                and type(response) is dict and response.get("disposition") == "response-observed"
                and response.get("operation_id") == auth.operation_id
                and response.get("payload_sha256") == auth.payload_sha256
                and positive(response.get("object_id")), "owned-original-response")
        payload = document(wire)
        shape(auth, payload)
        repository = api.call(f"repos/{ROOT}")
        require(repository.get("id") == ROOT_ID and repository.get("full_name") == ROOT
                and repository.get("visibility") == "public" and repository.get("private") is False,
                "owned-readback-target")
        listed = api.pages(f"repos/{ROOT}/pulls?state=all&head=ltn-it:{quote(payload['head'], safe='')}"
                           f"&base={quote(payload['base'], safe='')}&per_page=100")
        require(type(listed) is list, "owned-readback-inventory")
        matches = [p for p in listed if type(p) is dict and p.get("id") == response["object_id"]]
        require(len(matches) == 1 and positive(matches[0].get("number")), "owned-readback-identity")
        number = matches[0]["number"]
        observed = api.call(f"repos/{ROOT}/pulls/{number}")
        require(observed.get("id") == response["object_id"] and observed.get("number") == number
                and observed.get("state") == "open"
                and observed.get("user", {}).get("id") == auth.facts.publisher_actor_id
                and observed.get("user", {}).get("type") == "Bot"
                and observed.get("base", {}).get("repo", {}).get("id") == ROOT_ID
                and observed.get("head", {}).get("repo", {}).get("id") == ROOT_ID
                and observed.get("head", {}).get("sha") == auth.facts.head_sha
                and observed.get("head", {}).get("ref") == payload["head"]
                and observed.get("base", {}).get("ref") == payload["base"]
                and observed.get("title") == payload["title"]
                and observed.get("body") == payload.get("body")
                and observed.get("draft") is payload.get("draft", False), "owned-readback-mismatch")
        return {"operation_id": auth.operation_id, "payload_sha256": auth.payload_sha256,
                "disposition": "effect-confirmed", "object_id": response["object_id"], "number": number}
    except Exception:
        return {"disposition": "unknown-readback-required"}
