"""Fixed normal Collection release identities; no scope or producer admission."""
from __future__ import annotations

import re

from workflow_control import RELEASE

COLLECTIONS = {
    "ltn-it/ansible-collection-foundational": 1103405635,
    "ltn-it/ansible-collection-supplementary": 1103407173,
    "ltn-it/ansible-collection-rhel": 1103411913,
    "ltn-it/ansible-collection-ubuntu": 1268102957,
    "ltn-it/ansible-collection-ocp": 1103410706,
    "ltn-it/ansible-collection-cloud": 1318852819,
}
STABLE = re.compile(r"release/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def normal_release(pull, repository):
    """Recognize only a native same-repository stable release App PR to Main.

    This supplies neither a successful review nor publishing acceptance. The
    common executor must review the entire current revision and authenticate a
    genuine normal approval. Security's separately proven route stays separate.
    """
    identifier = COLLECTIONS.get(repository)
    if identifier is None:
        return False
    user = pull.get("user", {})
    base, head = pull.get("base", {}), pull.get("head", {})
    return (
        (user.get("login"), user.get("id"), user.get("type")) == RELEASE
        and base.get("ref") == "main"
        and type(head.get("ref")) is str
        and STABLE.fullmatch(head["ref"]) is not None
        and all(type((side.get("repo") or {}).get("id")) is int
                and (side.get("repo") or {}).get("id") == identifier
                and (side.get("repo") or {}).get("full_name") == repository for side in (base, head))
    )
