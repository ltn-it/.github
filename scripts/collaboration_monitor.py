"""Bounded current-surface observation; no notifier, mutation or cleanup client.

Reuses the existing visibility-aware observer. All origins are read, including
human edits to closed items. A clean result is only a declared current window,
not source admission, historical redaction or notification delivery.
"""
from datetime import datetime, timezone
import re
import time

from collaboration_content import require, validate_policy
from collaboration_inventory import organization_inventory, observe_open_collaboration
from collaboration_publisher import digest, json_bytes


class BoundedReader:
    def __init__(self, api, *, maximum_requests=5000, maximum_seconds=600, clock=time.monotonic):
        require(type(maximum_requests) is int and 1 <= maximum_requests <= 5000
                and type(maximum_seconds) is int and 1 <= maximum_seconds <= 600, 'monitor-bounds')
        self.api, self.clock = api, clock
        self.requests, self.maximum_requests = 0, maximum_requests
        self.started, self.maximum_seconds = clock(), maximum_seconds

    def check(self):
        elapsed = self.clock() - self.started
        require(0 <= elapsed <= self.maximum_seconds, 'monitor-time-bound')

    def get(self, path):
        require(type(path) is str and re.match(r'^(orgs/ltn-it(?:[/?]|$)|repos/ltn-it/)', path)
                and '..' not in path and '\n' not in path, 'monitor-read-path')
        self.check()
        require(self.requests < self.maximum_requests, 'monitor-request-bound')
        self.requests += 1
        result = self.api.get(path)
        self.check()  # Slow final GET must not turn an expired window clean.
        return result


def checked_metadata(report):
    # Provider metadata is not a free-form diagnostic channel either.
    for row in report['objects']:
        value = row['source_updated_at']
        if value is None:
            require(row['kind'] == 'review', 'monitor-source-timestamp')
        else:
            require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z', value),
                    'monitor-source-timestamp')
            datetime.fromisoformat(value.replace('Z', '+00:00'))
    return report


def signature(report):
    return digest(json_bytes({
        'scope': report['scope'], 'repository_ids': report['repository_ids'],
        'counts': report['counts'], 'excluded': report['excluded'],
        'pending_review_drafts_excluded': report['pending_review_drafts_excluded'],
        'objects': sorted([{k: row[k] for k in ('repository_id', 'kind', 'id', 'content_sha256',
                                               'categories', 'disposition', 'source_updated_at')}
                           for row in report['objects']], key=lambda x:(x['repository_id'], x['kind'], x['id']))}))


def monitor_current(api, policy, repositories=None, *, maximum_requests=5000, maximum_seconds=600,
                    clock=time.monotonic):
    """Two complete current-state reads and final authoritative inventory.

    None selects all public non-archived repositories from the fresh complete
    inventory. An explicit list is declared limited scope. Incomplete data,
    missing pages, stale/changed visibility, late edits or bounds yield unknown
    without retaining partial observations or echoing exception/provider text.
    No report here asserts actual owner notification or a polling cadence.
    """
    reader = BoundedReader(api, maximum_requests=maximum_requests,
                           maximum_seconds=maximum_seconds, clock=clock)
    started = datetime.now(timezone.utc).isoformat()
    try:
        validate_policy(policy)
        inventory = organization_inventory(reader)
        available = {row['full_name']: row for row in inventory['repositories']
                     if row['visibility'] == 'public' and not row['archived']}
        selected = sorted(available) if repositories is None else repositories
        require(type(selected) is list and selected and len(selected) == len(set(selected))
                and all(name in available for name in selected), 'monitor-public-scope')
        first = checked_metadata(observe_open_collaboration(reader, inventory, policy, selected, state='all'))
        second = checked_metadata(observe_open_collaboration(reader, inventory, policy, selected, state='all'))
        require(signature(first) == signature(second), 'monitor-window-drift')
        final = organization_inventory(reader)
        require(inventory['repositories'] == final['repositories'], 'monitor-inventory-drift')
        reader.check()
        return {'version':1, 'content_complete':True, 'current_surface_clean':second['clean'],
                'disposition':'declared-current-scope-clean' if second['clean'] else 'owner-remediation-required',
                'started_at':started, 'finished_at':datetime.now(timezone.utc).isoformat(),
                'scope':second['scope'], 'scope_selection':'all-public-active' if repositories is None else 'explicit',
                'configured_owner':policy['owner'], 'notification_delivery_proven':False,
                'inventory_sha256':digest(json_bytes(inventory)), 'final_inventory_sha256':digest(json_bytes(final)),
                'scope_signature_sha256':signature(second), 'observation':second,
                'requests':reader.requests, 'maximum_seconds':maximum_seconds,
                'residual_risks':['edits-after-last-read', 'cross-object-nonatomic-window',
                                  'invocation-cadence-not-proven', 'private-owner-delivery-not-proven']}
    except Exception:
        return {'version':1, 'content_complete':False, 'current_surface_clean':None,
                'disposition':'monitor-incomplete', 'notification_delivery_proven':False,
                'started_at':started, 'finished_at':datetime.now(timezone.utc).isoformat(),
                'requests':reader.requests, 'maximum_seconds':maximum_seconds}
