"""Private Actions candidate: real local code, recorded network/native edges."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import collaboration_management_candidate as m
from collaboration_content import AdmissionError, policy_from
from collaboration_publisher import BoundedTransport, TransportResult, digest, json_bytes
import test_collaboration_native_issuer as fixture


def encoded(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


class ManagementCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.NativeIssuerTests.setUpClass()
        cls.key,cls.keys=fixture.NativeIssuerTests.key,fixture.NativeIssuerTests.jwks

    def setUp(self):
        self.now=1800000000
        self.source,self.main,self.base,self.head=('a'*40,'b'*40,'c'*40,'d'*40)
        self.entry={'version':1,'management_main':self.main,'subject':'offline-private-principal',
            'job':'Publish checked collaboration','origin_producer_id':42,'publisher_actor_id':84,
            'role':'owned-sync','operation':'pull.create','journal_branch':m.JOURNAL_BRANCH,'journal_rule_id':700}
        self.journal_rule={'id':700,'target':'branch','source_type':'Repository','source':m.MANAGEMENT,
            'enforcement':'active','bypass_actors':[],'conditions':{'ref_name':{
                'include':[f'refs/heads/{m.JOURNAL_BRANCH}'],'exclude':[]}},
            'rules':[{'type':'deletion'},{'type':'non_fast_forward'}]}
        self.rule={'id':m.RULE,'enforcement':'active','target':'branch','conditions':{
            'repository_id':{'repository_ids':[m.MANAGEMENT_ID]},'ref_name':{
            'include':['refs/heads/develop','refs/heads/main'],'exclude':[]}},'rules':[{'type':'workflows',
            'parameters':{'workflows':[{'repository_id':m.ROOT_ID,'path':m.control.WORKFLOW,
                'ref':'refs/heads/main','sha':self.source}]}}]}
        self.workflow={'concurrency':{'group':m.CONCURRENCY,'cancel-in-progress':False},'jobs':{
            'collaboration-publish':{'name':self.entry['job'],'permissions':{
                'contents':'read','actions':'read','id-token':'write'}}}}
        self.private={'id':m.MANAGEMENT_ID,'full_name':m.MANAGEMENT,'visibility':'private','private':True,
                      'archived':False,'disabled':False}
        self.target={'id':m.ROOT_ID,'full_name':m.ROOT,'visibility':'public','private':False,
                     'archived':False,'disabled':False,'owner':{'login':'ltn-it','id':m.control.ORGANIZATION_ID}}
        self.run={'id':200,'run_attempt':1,'head_sha':self.main,'head_branch':'main','event':'workflow_dispatch',
                  'path':m.WORKFLOW,'repository':self.private,'status':'in_progress','conclusion':None}
        self.job={'id':300,'name':self.entry['job'],'run_id':200,'run_attempt':1,'head_sha':self.main,
                  'status':'in_progress','conclusion':None,'steps':[{'name':'Prepare exact owned publication',
                  'status':'completed','conclusion':'success'}]}
        self.payload={'title':'Collection guidance','body':'Public update.','head':'codex/collection-guidance',
                      'base':'develop','draft':True}
        self.wire=json_bytes(self.payload)
        self.manifest={'version':1,'role':'owned-sync','operation':'pull.create','repository_id':m.ROOT_ID,
            'run_id':200,'run_attempt':1,'job_id':300,'base_ref':'develop','head_ref':self.payload['head'],
            'base_sha':self.base,'head_sha':self.head,'payload_sha256':digest(self.wire)}
        self.policy=policy_from(Path(__file__).resolve().parents[1]/'.lit/collaboration-content-policy.json')
        stamp=datetime.fromtimestamp(self.now,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.inventory={'version':1,'organization':'ltn-it','complete':True,'started_at':stamp,'finished_at':stamp,
            'repositories':[{k:self.target[k] for k in ['id','full_name','visibility','archived']}]}
        self.api=SimpleNamespace(call=self.call,file=self.file,pages=self.pages,put_once=self.put_once)
        self.service=m.OwnedIssuer(self.api,'',self.wire,self.policy,self.inventory,clock=lambda:self.now,keys=lambda:self.keys)
        self.claims={'iss':'https://token.actions.githubusercontent.com','aud':self.service.audience,
            'sub':self.entry['subject'],'iat':self.now-20,'nbf':self.now-20,'exp':self.now+280,'jti':'offline-jti',
            'repository':m.MANAGEMENT,'repository_id':str(m.MANAGEMENT_ID),'repository_owner':'ltn-it',
            'repository_owner_id':str(m.control.ORGANIZATION_ID),'repository_visibility':'private',
            'event_name':'workflow_dispatch','ref':'refs/heads/main','sha':self.main,'workflow_sha':self.main,
            'workflow_ref':f'{m.MANAGEMENT}/{m.WORKFLOW}@refs/heads/main','run_id':'200','run_attempt':'1','check_run_id':'300'}
        self.sign();self.tip='e'*40;self.files={};self.writes=[];self.history=[];self.journal_history=set()
        self.missing=False;self.unknown=False;self.response_fail=False;self.drift=False
        self.download=patch.object(m.subprocess,'run',side_effect=self.download_artifact)
        self.download_mock=self.download.start();self.addCleanup(self.download.stop)
        self.sender=Mock(return_value=TransportResult(201,1000))
        self.transport=BoundedTransport(self.sender,publisher_actor_id=84)

    def sign(self):
        h=encoded(json_bytes({'alg':'RS256','typ':'JWT','kid':'offline-key'}))
        unsigned=h+'.'+encoded(json_bytes(self.claims))
        self.service.token=unsigned+'.'+encoded(self.key.sign(unsigned.encode(),padding.PKCS1v15(),hashes.SHA256()))

    def call(self,path):
        if path==f'repos/{m.MANAGEMENT}/rulesets/700':return copy.deepcopy(self.journal_rule)
        if path.startswith('orgs/ltn-it/repos?type=all'):
            return [copy.deepcopy(self.target)] if path.endswith('page=1') else []
        data={'orgs/ltn-it':{'id':m.control.ORGANIZATION_ID,'login':'ltn-it','public_repos':1,'owned_private_repos':0},
            'orgs/ltn-it/memberships/litroc':{'state':'active','role':'admin','organization':{'login':'ltn-it'}},
            f'orgs/ltn-it/rulesets/{m.RULE}':self.rule,f'repos/{m.MANAGEMENT}':self.private,
            f'repos/{m.MANAGEMENT}/git/ref/heads/main':{'object':{'sha':self.main}},
            f'repos/{m.MANAGEMENT}/actions/runs/200':self.run,f'repos/{m.ROOT}':self.target,
            f'repos/{m.ROOT}/git/ref/heads/develop':{'object':{'sha':self.base}},
            f'repos/{m.ROOT}/git/ref/heads/codex/collection-guidance':{'object':{'sha':self.head}},
            f'repos/{m.MANAGEMENT}/git/ref/heads/{m.JOURNAL_BRANCH}':{'object':{'sha':self.tip}}}
        if path not in data:raise AssertionError('unexpected read')
        return copy.deepcopy(data[path])

    def file(self,repo,path,revision):
        if (repo,path,revision) in self.files:return self.files[(repo,path,revision)]
        if repo==m.ROOT and revision==self.source:
            if path==m.POLICY:return json_bytes(self.policy)
            if path==m.REGISTRY:
                if self.missing:raise FileNotFoundError()
                return json_bytes(self.entry)
        if (repo,path,revision)==(m.MANAGEMENT,m.WORKFLOW,self.main):return json_bytes(self.workflow)
        raise AssertionError('unexpected file')

    def pages(self,path,key=None):
        if f'repos/{m.MANAGEMENT}/commits?' in path:
            from urllib.parse import parse_qs
            path_value=parse_qs(path.split('?',1)[1])['path'][0]
            return [{'sha':self.tip}] if path_value in self.journal_history else []
        if path.endswith('/attempts/1/jobs'):return [copy.deepcopy(self.job)]
        if path.endswith('/artifacts'):return [{'name':'collaboration-owned-operation-1','expired':False,'size_in_bytes':1024}]
        if '/pulls?state=all&head=' in path:return copy.deepcopy(self.history)
        raise AssertionError('unexpected list')

    def download_artifact(self,args,**kwargs):
        self.assertEqual(args[:-1],['gh','run','download','200','--repo',m.MANAGEMENT,
            '--name','collaboration-owned-operation-1','--dir'])
        (Path(args[-1])/'operation.json').write_bytes(json_bytes(self.manifest))
        return SimpleNamespace(returncode=0)

    def put_once(self,path,value):
        self.writes.append((path,copy.deepcopy(value)));self.assertEqual(set(value),{'message','content','branch'})
        key=path.split('/contents/')[1]
        if any(k[1]==key for k in self.files):return 422,{}
        wire=base64.b64decode(value['content']);parent=self.tip
        commit=hashlib.sha1((parent+digest(wire)).encode(),usedforsecurity=False).hexdigest()
        self.files[(m.MANAGEMENT,key,commit)]=wire;self.tip=commit;self.journal_history.add(key)
        if self.unknown or (self.response_fail and key.endswith('/response.json')):raise TimeoutError('private data')
        if self.drift:self.job['status']='completed';self.job['conclusion']='failure'
        blob=hashlib.sha1(b'blob '+str(len(wire)).encode()+b'\0'+wire,usedforsecurity=False).hexdigest()
        return 201,{'content':{'sha':blob},'commit':{'sha':commit,'parents':[{'sha':parent}]}}

    def execute(self):
        return m.publish_owned(self.service,self.api,self.transport,self.wire,self.inventory,self.policy,
            clock=lambda:datetime.fromtimestamp(self.now,timezone.utc))

    def blocked(self,calls=0):
        self.assertEqual({'disposition':'blocked-before-publication'},self.execute());self.assertEqual(calls,self.sender.call_count)

    def test_actual_private_signature_manifest_and_create_only_journal_send_exact_bytes(self):
        auth=self.service.issue();self.assertEqual(self.main,auth.facts.origin_source)
        self.assertEqual('response-observed',self.execute()['disposition'])
        self.sender.assert_called_once_with('POST','https://api.github.com/repos/ltn-it/.github/pulls',self.wire)
        self.assertEqual(2,len(self.writes));self.assertTrue(self.writes[0][0].endswith('/intent.json'))
        self.assertTrue(self.writes[1][0].endswith('/response.json'))

    def test_replay_never_sends_twice(self):self.execute();self.blocked(calls=1)

    def test_changed_payload_cannot_buy_new_operation(self):
        auth=self.service.issue();self.execute();self.payload['body']='Different public text.'
        self.wire=json_bytes(self.payload);self.service.wire=self.wire;self.manifest['payload_sha256']=digest(self.wire)
        self.service.audience=m.AUDIENCE+digest(self.wire);self.claims['aud']=self.service.audience;self.sign()
        self.assertEqual(auth.operation_id,self.service.issue().operation_id);self.blocked(calls=1)

    def test_unknown_journal_consumes_without_public_effect(self):
        self.unknown=True;self.blocked();self.unknown=False;self.blocked();self.assertEqual(1,len(self.writes))

    def test_native_generation_drift_after_claim_prevents_effect(self):
        self.drift=True;self.blocked();self.assertEqual(1,len(self.writes))

    def test_response_commit_failure_is_unknown_and_not_retried(self):
        self.response_fail=True;self.assertEqual('unknown-readback-required',self.execute()['disposition']);self.blocked(calls=1)

    def test_http_unknown_record_does_not_authorize_retry(self):
        self.sender.return_value=TransportResult(0,None)
        self.assertEqual('unknown-readback-required',self.execute()['disposition']);self.blocked(calls=1)

    def test_missing_current_registration_does_not_admit_candidate(self):
        self.missing=True;self.blocked();self.assertEqual([],self.writes)

    def test_private_identity_and_attempt_are_not_relabelable(self):
        for field,value in [('repository',m.ROOT),('repository_visibility','public'),('run_attempt','2'),
                            ('workflow_sha','f'*40),('ref','refs/heads/develop'),('exp',self.now-1)]:
            with self.subTest(field=field):
                old=self.claims[field];self.claims[field]=value;self.sign();self.blocked();self.claims[field]=old
        self.sign();self.assertEqual([],self.writes)

    def test_tampered_signed_claims_fail_before_journal(self):
        a,b,c=self.service.token.split('.');self.service.token=a+'.'+encoded(json_bytes(self.claims|{'jti':'bad'}))+'.'+c
        self.blocked();self.assertEqual([],self.writes)

    def test_wrong_scope_role_private_visibility_job_or_preparation(self):
        for obj,key,value in [(self.rule,'enforcement','evaluate'),(self.entry,'role','hosted-copilot'),
                (self.private,'visibility','public'),(self.job,'name','Promotion preparation'),
                (self.job['steps'][0],'conclusion','skipped')]:
            with self.subTest(key=key):
                old=obj[key];obj[key]=value;self.blocked();obj[key]=old
        self.assertEqual([],self.writes)

    def test_single_native_writer_contract_required(self):
        for value in [None,{'group':'other','cancel-in-progress':False},{'group':m.CONCURRENCY,'cancel-in-progress':True}]:
            self.workflow['concurrency']=value;self.blocked()

    def test_prior_open_or_closed_exact_subject_blocks(self):
        for state in ['open','closed']:
            self.history=[{'state':state,'head':{'sha':self.head}}];self.blocked()
        self.assertEqual([],self.writes)

    def test_private_payload_stops_before_journal_and_keys(self):
        self.payload['body']='https://issues.cloud.ltn-it.de/browse/LTN-999'
        self.wire=json_bytes(self.payload);self.service.wire=self.wire;self.manifest['payload_sha256']=digest(self.wire)
        self.service.audience=m.AUDIENCE+digest(self.wire);self.claims['aud']=self.service.audience;self.sign()
        self.blocked();self.assertEqual([],self.writes)

    def test_real_https_journal_one_fixed_create_without_sha_or_retry(self):
        client=m.PrivateJournalClient(self.api,lambda:'offline_journal_token_123456789')
        conn=Mock();response=conn.getresponse.return_value;response.status=201
        response.read.return_value=b'{"content":{},"commit":{}}'
        path=f'repos/{m.MANAGEMENT}/contents/.lit/collaboration-journal/'+('a'*64)+'/intent.json'
        value={'message':'Record hashes','content':'e30=','branch':m.JOURNAL_BRANCH}
        with patch.object(m.http.client,'HTTPSConnection',return_value=conn) as factory:
            self.assertEqual(201,client.put_once(path,value)[0]);self.assertTrue(factory.call_args.kwargs['context'].check_hostname)
            self.assertEqual(('PUT','/'+path),conn.request.call_args.args)
            self.assertEqual(json_bytes(value),conn.request.call_args.kwargs['body'])
            for invalid in [value|{'sha':'f'*40},value|{'branch':'main'}]:
                with self.assertRaises(AdmissionError):client.put_once(path,invalid)
            response.status=302
            with self.assertRaises(AdmissionError) as caught:client.put_once(path,value)
            self.assertEqual('owned-journal-create-unknown',str(caught.exception));self.assertEqual(2,conn.request.call_count)
        with self.assertRaises(AdmissionError):client.put_once('repos/ltn-it/.github/contents/file',value)

    def test_concurrent_same_operation_model_yields_one_effect(self):
        # Only the remote atomic-create boundary is modeled. Both callers run
        # the actual issuer, validator, journal client contract and publisher.
        original=self.api.put_once;lock=threading.Lock()
        def atomic(path,value):
            with lock:return original(path,value)
        self.api.put_once=atomic
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.execute(),range(2)))
        self.assertEqual(1,self.sender.call_count)
        self.assertEqual(['blocked-before-publication','response-observed'],sorted(x['disposition'] for x in results))

    def test_wrong_journal_parent_or_blob_consumes_but_does_not_send(self):
        original=self.api.put_once
        def drift(path,value):
            status,response=original(path,value)
            response['commit']['parents']=[{'sha':'f'*40}]
            return status,response
        self.api.put_once=drift;self.blocked();self.assertEqual(1,len(self.writes))

    def test_extra_native_artifact_member_is_not_an_authority(self):
        original=self.download_artifact
        def extra(args,**kwargs):
            result=original(args,**kwargs)
            (Path(args[-1])/'unexpected.json').write_bytes(b'{}')
            return result
        self.download_mock.side_effect=extra
        self.blocked();self.assertEqual([],self.writes)

    def test_deleted_current_intent_does_not_restore_authority(self):
        self.execute();self.files.clear();self.blocked(calls=1)
        self.assertEqual(2,len(self.writes))

    def test_unprotected_journal_ref_cannot_reserve_or_publish(self):
        self.journal_rule['enforcement']='evaluate'
        self.blocked();self.assertEqual([],self.writes)

    def test_unknown_bypass_and_foreign_journal_scope_fail_before_write(self):
        for field,value in [('bypass_actors',None),('bypass_actors',[{'actor_type':'Integration','actor_id':84}]),
                            ('source',m.ROOT),('conditions',{'ref_name':{'include':['refs/heads/main'],'exclude':[]}})]:
            with self.subTest(field=field):
                old=self.journal_rule[field];self.journal_rule[field]=value;self.blocked();self.journal_rule[field]=old
        self.assertEqual([],self.writes)


    def credential_flow(self, *, extra=False, unknown=False, drift=False):
        from cryptography.hazmat.primitives import serialization
        from collaboration_app_credential import AppIdentity
        pem=self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
        self.key_getter=Mock(return_value=pem);self.network=[]
        expiry=datetime.fromtimestamp(self.now+3600,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        values={'/app':{'id':100,'slug':'offline-publisher'},
            '/app/installations/200':{'id':200,'app_id':100,'suspended_at':None,
                'account':{'id':m.control.ORGANIZATION_ID,'login':'ltn-it','type':'Organization'},
                'permissions':{'pull_requests':'write'}},
            '/users/offline-publisher%5Bbot%5D':{'id':84,'login':'offline-publisher[bot]','type':'Bot'},
            '/app/installations/200/access_tokens':{'token':'ghs_'+'x'*80,'expires_at':expiry,
                'permissions':{'pull_requests':'write','metadata':'read'}},
            '/installation/repositories?per_page=100&page=1':{'total_count':1,
                'repositories':[{'id':m.ROOT_ID,'full_name':m.ROOT,'private':False}]},
            '/repos/ltn-it/.github/pulls':{'id':1000}}
        if extra:values['/app/installations/200/access_tokens']['permissions']['contents']='write'
        def connect(host,**kwargs):
            self.assertEqual('api.github.com',host);self.assertTrue(kwargs['context'].check_hostname)
            conn=Mock()
            def response():
                method,path=conn.request.call_args.args;params=conn.request.call_args.kwargs
                self.network.append((method,path,params))
                if path.endswith('/access_tokens') and unknown:raise TimeoutError('not disclosed')
                if path.startswith('/installation/repositories') and drift:self.main='9'*40
                return Mock(status=201 if method=='POST' else 200,
                            read=Mock(return_value=json_bytes(values[path])))
            conn.getresponse.side_effect=response
            return conn
        def execute():
            return m.prepare_and_publish_owned(self.service,self.api,AppIdentity(100,200,84),
                self.key_getter,self.wire,self.inventory,self.policy)
        return execute,connect

    def test_real_preparer_and_https_sender_composed_with_private_intents(self):
        execute,connect=self.credential_flow()
        with patch.object(m.http.client,'HTTPSConnection',side_effect=connect):
            self.assertEqual('response-observed',execute()['disposition'])
            self.assertEqual({'disposition':'blocked-before-publication'},execute())
        posts=[n for n in self.network if n[0]=='POST']
        self.assertEqual(['/app/installations/200/access_tokens','/repos/ltn-it/.github/pulls'],
                         [n[1] for n in posts])
        self.assertEqual({'repository_ids':[m.ROOT_ID],'permissions':{'pull_requests':'write'}},
                         m.document(posts[0][2]['body']))
        self.assertEqual(self.wire,posts[1][2]['body']);self.assertEqual(3,len(self.writes))

    def test_real_credential_extra_permission_never_reaches_public_sender(self):
        execute,connect=self.credential_flow(extra=True)
        with patch.object(m.http.client,'HTTPSConnection',side_effect=connect):
            self.assertEqual({'disposition':'blocked-before-publication'},execute())
        self.assertEqual(1,len(self.writes));self.assertFalse(any('/repos/' in n[1] for n in self.network))

    def test_unknown_mint_has_no_retry_or_publication(self):
        execute,connect=self.credential_flow(unknown=True)
        with patch.object(m.http.client,'HTTPSConnection',side_effect=connect):
            execute();execute()
        self.assertEqual(1,len([n for n in self.network if n[0]=='POST']))
        self.assertEqual(1,len(self.writes));self.assertFalse(any('/repos/' in n[1] for n in self.network))

    def test_native_drift_after_all_token_reads_blocks_original_publication(self):
        execute,connect=self.credential_flow(drift=True)
        with patch.object(m.http.client,'HTTPSConnection',side_effect=connect):
            self.assertEqual({'disposition':'blocked-before-publication'},execute())
        self.assertEqual(5,len(self.network));self.assertEqual(1,len(self.writes))

    def test_unregistered_owned_candidate_never_reads_app_key(self):
        execute,connect=self.credential_flow();self.missing=True
        with patch.object(m.http.client,'HTTPSConnection',side_effect=connect):
            self.assertEqual({'disposition':'blocked-before-publication'},execute())
        self.key_getter.assert_not_called();self.assertEqual([],self.network);self.assertEqual([],self.writes)

    def readback_fixture(self):
        auth=self.service.issue()
        response={'operation_id':auth.operation_id,'payload_sha256':auth.payload_sha256,
                  'disposition':'response-observed','object_id':1000}
        obj={'id':1000,'number':15,'state':'open','user':{'id':84,'type':'Bot'},
             'base':{'repo':{'id':m.ROOT_ID},'ref':'develop'},
             'head':{'repo':{'id':m.ROOT_ID},'ref':self.payload['head'],'sha':self.head},
             'title':self.payload['title'],'body':self.payload['body'],'draft':True}
        reader=SimpleNamespace(call=Mock(side_effect=[self.target,obj]),
                               pages=Mock(return_value=[{'id':1000,'number':15}]))
        return auth,response,obj,reader

    def test_readback_resolves_number_from_original_id_not_equal_text(self):
        auth,response,obj,reader=self.readback_fixture()
        result=m.readback_owned(reader,auth,self.wire,response)
        self.assertEqual({'operation_id':auth.operation_id,'payload_sha256':auth.payload_sha256,
            'disposition':'effect-confirmed','object_id':1000,'number':15},result)
        self.assertEqual(f'repos/{m.ROOT}/pulls/15',reader.call.call_args.args[0])
        self.assertNotIn('body',result)

    def test_missing_original_response_never_searches_for_equal_content(self):
        auth,response,obj,reader=self.readback_fixture();response['disposition']='unknown-readback-required'
        self.assertEqual({'disposition':'unknown-readback-required'},m.readback_owned(reader,auth,self.wire,response))
        reader.call.assert_not_called();reader.pages.assert_not_called()

    def test_readback_actor_refs_body_or_draft_drift_stays_unknown(self):
        for field in ['actor','head','base','body','draft']:
            with self.subTest(field=field):
                auth,response,obj,reader=self.readback_fixture()
                if field=='actor':obj['user']['id']=999
                if field=='head':obj['head']['sha']='9'*40
                if field=='base':obj['base']['repo']['id']=999
                if field=='body':obj['body']='Different response.'
                if field=='draft':obj['draft']=False
                self.assertEqual({'disposition':'unknown-readback-required'},m.readback_owned(reader,auth,self.wire,response))

    def test_duplicate_or_different_original_identity_cannot_confirm(self):
        for rows in [[{'id':999,'number':15}],[{'id':1000,'number':15}]*2]:
            auth,response,obj,reader=self.readback_fixture();reader.pages.return_value=rows
            self.assertEqual({'disposition':'unknown-readback-required'},m.readback_owned(reader,auth,self.wire,response))
            self.assertEqual(1,reader.call.call_count)

    def test_original_response_operation_binding_precedes_all_reads(self):
        auth,response,obj,reader=self.readback_fixture();response['operation_id']='9'*64
        self.assertEqual({'disposition':'unknown-readback-required'},m.readback_owned(reader,auth,self.wire,response))
        reader.call.assert_not_called();reader.pages.assert_not_called()

if __name__=='__main__':unittest.main()
