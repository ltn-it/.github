"""Exercise existing observer through complete bounded current-surface path."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import collaboration_content as content
import collaboration_inventory as inventory
import collaboration_monitor as monitor
import test_collaboration_content as fixture


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.PullObservationTests();self.f.setUp()
        self.policy=self.f.policy
        self.rows=[dict(r,owner={'login':'ltn-it'},private=r['visibility']!='public')
                   for r in self.f.inventory['repositories']]
        self.responses={k.replace('state=open','state=all'):v for k,v in self.f.responses.items()}
        self.responses.update({'orgs/ltn-it':{'id':1,'login':'ltn-it','public_repos':1,'owned_private_repos':1},
          'orgs/ltn-it/memberships/litroc':{'state':'active','role':'admin','organization':{'login':'ltn-it'}},
          'orgs/ltn-it/repos?type=all&per_page=100&page=1':self.rows,
          'orgs/ltn-it/repos?type=all&per_page=100&page=2':[]})
        self.api=fixture.FakeAPI(self.responses)
        # Monitor takes fresh inventory timestamps from the real clock.
        now=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.f.pull['updated_at']=now;self.f.comment['updated_at']=now;self.f.inline['updated_at']=now

    def execute(self,**kwargs):return monitor.monitor_current(self.api,self.policy,**kwargs)

    def test_closed_pull_human_review_edit_included_without_value_echo(self):
        self.f.pull['state']='closed'
        result=self.execute()
        self.assertTrue(result['content_complete']);self.assertFalse(result['current_surface_clean'])
        self.assertEqual('all-public-active',result['scope_selection'])
        self.assertNotIn('closed-pull-requests',result['observation']['excluded'])
        self.assertNotIn('closed-issues',result['observation']['excluded'])
        self.assertNotIn('TEST-123',json.dumps(result))
        self.assertFalse(result['notification_delivery_proven'])
        self.assertEqual(1,result['observation']['counts']['reviews'])

    def test_closed_issue_and_comment_are_not_excluded(self):
        f=fixture.ObservationTests();f.setUp();f.item['state']='closed'
        self.responses.update({k.replace('state=open','state=all'):v for k,v in f.responses.items()})
        # Same declared API would also list a PR; both current surfaces are read.
        result=self.execute()
        self.assertTrue(result['content_complete']);self.assertFalse(result['current_surface_clean'])
        self.assertEqual(1,result['observation']['counts']['issues'])
        self.assertEqual(1,result['observation']['counts']['comments'])

    def test_clean_is_exact_declared_scope_not_notification_or_atomic_proof(self):
        self.f.review['body']='Public safe'
        result=self.execute(repositories=['ltn-it/.github'])
        self.assertTrue(result['content_complete']);self.assertTrue(result['current_surface_clean'])
        self.assertEqual('explicit',result['scope_selection'])
        self.assertIn('edit-history',result['observation']['excluded'])
        self.assertIn('edits-after-last-read',result['residual_risks'])
        self.assertFalse(result['notification_delivery_proven'])

    def test_incomplete_review_pagination_is_unknown_not_empty_clean(self):
        self.responses['repos/ltn-it/.github/pulls/3/reviews?per_page=100&page=2']=ValueError('private raw')
        result=self.execute()
        self.assertFalse(result['content_complete']);self.assertIsNone(result['current_surface_clean'])
        self.assertNotIn('private raw',json.dumps(result));self.assertNotIn('observation',result)

    def test_late_edit_between_complete_passes_cannot_reuse_first_clean_result(self):
        self.f.review['body']='Safe';original=self.api.get;reads=[]
        def get(path):
            value=original(path)
            if path=='repos/ltn-it/.github/pulls/3/reviews?per_page=100&page=1':
                reads.append(path)
                if len(reads)>2:value[0]['body']='New private TEST-777'
            return value
        self.api.get=get
        result=self.execute();self.assertFalse(result['content_complete']);self.assertIsNone(result['current_surface_clean'])
        self.assertNotIn('TEST-777',json.dumps(result))

    def test_final_inventory_change_or_unreadable_visibility_is_unknown(self):
        original=self.api.get;reads=[]
        def get(path):
            value=original(path)
            if path=='orgs/ltn-it/repos?type=all&per_page=100&page=1':
                reads.append(path)
                if len(reads)>1:value[0]['visibility']='private';value[0]['private']=True
            return value
        self.api.get=get
        self.assertFalse(self.execute()['content_complete'])

    def test_invalid_or_private_selected_scope_is_never_silently_skipped(self):
        for selected in [[],['ltn-it/example'],['ltn-it/.github']*2,['unknown']]:
            with self.subTest(selected=selected):self.assertFalse(self.execute(repositories=selected)['content_complete'])

    def test_request_bound_exhaustion_and_slow_final_get_are_unknown(self):
        result=self.execute(maximum_requests=1)
        self.assertFalse(result['content_complete']);self.assertEqual(1,result['requests'])
        clock=iter([0,0,601]).__next__
        result=self.execute(clock=clock)
        self.assertFalse(result['content_complete']);self.assertIsNone(result['current_surface_clean'])

    def test_observer_default_open_contract_is_preserved(self):
        self.assertTrue(any('state=all' in key for key in self.responses))
        other=fixture.PullObservationTests();other.setUp()
        report=other.observe()
        self.assertEqual('open-issues-and-pulls-current-comments-submitted-reviews-inline-comments',report['scope'])
        self.assertIn('closed-pull-requests',report['excluded'])

    def test_malformed_metadata_cannot_be_echoed_in_private_or_public_report(self):
        self.f.comment['updated_at']='TEST-888 private metadata'
        result=self.execute()
        self.assertFalse(result['content_complete']);self.assertNotIn('TEST-888',json.dumps(result))

    def test_unknown_state_is_rejected_before_reads(self):
        with self.assertRaises(content.AdmissionError):
            inventory.observe_open_collaboration(self.api,{},self.policy,['ltn-it/.github'],state='unknown')
        self.assertEqual([],self.api.calls)

if __name__=='__main__':unittest.main()
