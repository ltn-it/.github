"""Concrete bounded HTTPS sender, to run inside the trusted broker boundary.

This module does not install a broker, authenticate an issuer, obtain a token,
or isolate Python processes. Only an independently admitted Publisher may call
it after durable reservation and the final native attestation. No CLI exists.
"""
import http.client
import json
import re
import ssl

from collaboration_content import require
from collaboration_publisher import TransportResult, positive


HOST = "api.github.com"
PREFIX = "https://api.github.com/repos/ltn-it/.github/"
MAX_REQUEST = 262144
MAX_RESPONSE = 1048576
TIMEOUT = 15
NUMBER = r"[1-9][0-9]*"
PATHS = {
    "POST": (r"issues", r"pulls", rf"issues/{NUMBER}/comments",
             rf"pulls/{NUMBER}/comments", rf"pulls/{NUMBER}/comments/{NUMBER}/replies",
             rf"pulls/{NUMBER}/reviews"),
    "PATCH": (rf"issues/{NUMBER}", rf"pulls/{NUMBER}",
              rf"issues/comments/{NUMBER}", rf"pulls/comments/{NUMBER}"),
    "PUT": (rf"pulls/{NUMBER}/reviews/{NUMBER}",),
}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "publisher-response-shape")
        value[key] = item
    return value


class HTTPSOnceSender:
    """One request, no redirect/retry, fixed verified GitHub TLS connection.

    credential() is private broker code, never a contributor callback. Its
    actual credential/installation/actor/scope must be independently admitted
    and checked by the surrounding runtime. Passing a token here proves none
    of those facts. This class never emits tokens, payloads, or response bodies.
    """

    def __init__(self, credential):
        require(callable(credential), "publisher-credential-source")
        self._credential = credential

    def __call__(self, method, url, wire):
        require(type(method) is str and method in PATHS and type(url) is str
                and url.startswith(PREFIX), "publisher-https-route")
        suffix = url[len(PREFIX):]
        require(any(re.fullmatch(pattern, suffix) for pattern in PATHS[method]),
                "publisher-https-route")
        require(type(wire) is bytes and 0 < len(wire) <= MAX_REQUEST, "publisher-https-bytes")
        # No caller URL parsing, environment proxy, custom CA, headers, TLS
        # context, timeout or connection factory crosses this boundary.
        connection = None
        try:
            token = self._credential()
            require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_]{20,512}", token),
                    "publisher-credential")
            connection = http.client.HTTPSConnection(HOST, timeout=TIMEOUT,
                                                    context=ssl.create_default_context())
            connection.request(method, "/repos/ltn-it/.github/" + suffix, body=wire,
                               headers={"Authorization": "Bearer " + token,
                                        "Accept": "application/vnd.github+json",
                                        "X-GitHub-Api-Version": "2022-11-28",
                                        "Content-Type": "application/json; charset=utf-8",
                                        "Content-Length": str(len(wire)),
                                        "User-Agent": "ltn-it-final-byte-publisher",
                                        "Connection": "close"})
            response = connection.getresponse()
            if type(response.status) is not int or response.status not in (200, 201):
                return TransportResult(0, None)
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                return TransportResult(0, None)
            value = json.loads(raw, object_pairs_hook=unique_object)
            if type(value) is not dict or not positive(value.get("id")):
                return TransportResult(0, None)
            return TransportResult(response.status, value["id"])
        except Exception:
            # Connection errors can occur after GitHub has accepted the write.
            # Never retry or disclose the exception; the reserved slot remains
            # consumed and only an authenticated readback can resolve it.
            return TransportResult(0, None)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
