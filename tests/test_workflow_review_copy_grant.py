"""No-network grant observation; the same harness can run the pinned bundle."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_review_copy as copy

NODE = r'''
const fs = require('node:fs'), crypto = require('node:crypto');
const root = process.env.RUNNER_TEMP, scenario = process.env.COPY_SCENARIO;
const calls = []; let original, unchanged = false;
const grant = {token: 'synthetic-token-never-a-live-credential',
  expires_at: new Date(Date.now()+3500000).toISOString(), permissions: {contents:'read',metadata:'read'},
  repository_selection:'selected', repositories:[{id:1120841013,full_name:'ltn-it/shared-assets-lit',name:'shared-assets-lit',private:true}]};
if (scenario==='write') grant.permissions.contents='write';
if (scenario==='extra_permission') grant.permissions.actions='read';
if (scenario==='all') grant.repository_selection='all';
if (scenario==='extra_repo') grant.repositories.push({id:99});
if (scenario==='wrong_repo') grant.repositories[0].id=99;
if (scenario==='expired') grant.expires_at=new Date(Date.now()-1000).toISOString();
if (scenario==='long_expiry') grant.expires_at=new Date(Date.now()+7200000).toISOString();
if (scenario==='no_permissions') delete grant.permissions;
globalThis.fetch = async (url, options) => {
  calls.push({url:String(url),method:options.method});
  if (String(url).endsWith('/installation')) return new Response(JSON.stringify({id:scenario==='wrong_installation'?1:148019054,
    app_id:4355159,app_slug:'lightning-it-release-automation',account:{id:54334171},suspended_at:null}),
    {status:200,headers:{'content-type':'application/json'}});
  if (String(url).endsWith('/access_tokens')) {
    original = new Response(scenario==='malformed'?'not JSON':JSON.stringify(grant),
      {status:201,headers:{'content-type':'application/json'}});
    return original;
  }
  throw new Error('No real network is available in this harness');
};
require(process.env.COPY_OBSERVER);
const observedFetch = globalThis.fetch;
globalThis.fetch = async (...args) => {
  const response = await observedFetch(...args);
  if (String(args[0]).endsWith('/access_tokens')) unchanged = response === original;
  return response;
};
if (process.env.COPY_BUNDLE) {
  const key=crypto.generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'pem',type:'pkcs8'});
  Object.assign(process.env,{'INPUT_CLIENT-ID':'Iv23liSIvZRkHWKxczlb','INPUT_PRIVATE-KEY':key,
    INPUT_OWNER:'ltn-it',INPUT_REPOSITORIES:'shared-assets-lit','INPUT_PERMISSION-CONTENTS':'read',
    'INPUT_SKIP-TOKEN-REVOKE':'false','INPUT_GITHUB-API-URL':scenario==='foreign_host'?'https://example.invalid':'https://api.github.com',
    GITHUB_REPOSITORY:'ltn-it/ansible-collection-cloud',GITHUB_REPOSITORY_OWNER:'ltn-it',
    GITHUB_OUTPUT:root+'/outputs',GITHUB_STATE:root+'/state'});
  fs.writeFileSync(root+'/outputs','');fs.writeFileSync(root+'/state','');
  require(process.env.COPY_BUNDLE);
} else {
  (async()=>{
    try {
      const url=scenario==='foreign_host'?'https://example.invalid/app/installations/148019054/access_tokens':
        `https://api.github.com/app/installations/${scenario==='wrong_installation'?1:148019054}/access_tokens`;
      const options={method:'POST',body:JSON.stringify({repositories:['shared-assets-lit'],permissions:{contents:'read'}})};
      const returned=await fetch(url,options);
      if(returned!==original) throw new Error('Native response object was replaced');
      if(scenario==='second_mint') {try {await fetch(url,options);} catch {}}
    } catch {}
  })();
}
let secondStarted=false;
process.on('beforeExit',()=>{
  if(process.env.COPY_BUNDLE && scenario==='second_mint' && !secondStarted) {
    secondStarted=true;delete require.cache[require.resolve(process.env.COPY_BUNDLE)];require(process.env.COPY_BUNDLE);return;
  }
  const receipt=root+'/review-copy-grant-30-1.json';
  fs.writeFileSync(root+'/result.json',JSON.stringify({calls,native_response_unchanged:unchanged,receipt:fs.existsSync(receipt)?JSON.parse(fs.readFileSync(receipt)):null}));
});
'''


class GrantTests(unittest.TestCase):
    def run_node(self, scenario="valid", *, bundle=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = {"workflow_repository": copy.SOURCE, "workflow_file_path": copy.WORKFLOW,
                   "workflow_sha": "9" * 40, "check_run_id": 400}
            env = {"PATH": os.environ["PATH"], "HOME": directory, "RUNNER_TEMP": directory,
                   "GITHUB_RUN_ID": "30", "GITHUB_RUN_ATTEMPT": "1", "NATIVE_JOB": json.dumps(job),
                   "COPY_OBSERVER": str(Path(copy.__file__).with_name("workflow_review_copy_grant.cjs")),
                   "COPY_SCENARIO": scenario}
            if bundle: env["COPY_BUNDLE"] = str(bundle)
            result = subprocess.run(["node", "-e", NODE], env=env, capture_output=True, timeout=30, check=False)
            data = json.loads((root / "result.json").read_text())
            data["exit_code"] = result.returncode
            if (root / "outputs").exists():
                outputs = (root / "outputs").read_text()
                data["action_token_matches_observation"] = bool(data["receipt"]) and (
                    "synthetic-token-never-a-live-credential" in outputs
                    and data["receipt"]["token_sha256"] == hashlib.sha256(b"synthetic-token-never-a-live-credential").hexdigest())
            if data["receipt"]:
                with patch.dict(os.environ, env, clear=True):
                    data["consumer_grant"] = copy.read_grant("synthetic-token-never-a-live-credential")
                    self.assertFalse(copy.grant_path().exists())
            return data

    def test_response_identity_and_complete_native_grant_are_retained(self):
        result = self.run_node()
        self.assertEqual(0, result["exit_code"])
        self.assertTrue(result["native_response_unchanged"])
        self.assertEqual({"contents": "read", "metadata": "read"}, result["consumer_grant"]["permissions"])
        self.assertNotIn("synthetic-token-never-a-live-credential", json.dumps(result))

    def test_invalid_scope_expiry_or_response_never_produces_a_usable_receipt(self):
        for scenario in ("write", "extra_permission", "all", "extra_repo", "wrong_repo", "expired", "long_expiry", "no_permissions", "malformed"):
            with self.subTest(scenario=scenario):
                result = self.run_node(scenario)
                self.assertIsNone(result["receipt"])
                self.assertEqual(1, len(result["calls"]))

    def test_foreign_host_wrong_installation_and_second_mint_are_blocked_before_network(self):
        for scenario in ("foreign_host", "wrong_installation", "second_mint"):
            with self.subTest(scenario=scenario):
                result = self.run_node(scenario)
                self.assertEqual(int(scenario == "second_mint"), len(result["calls"]))

    def test_receipt_must_match_this_actual_token_and_native_generation(self):
        result = self.run_node(); receipt = result["receipt"]
        with tempfile.TemporaryDirectory() as directory:
            job = {"workflow_repository": copy.SOURCE, "workflow_file_path": copy.WORKFLOW,
                   "workflow_sha": "9" * 40, "check_run_id": 400}
            env = {"RUNNER_TEMP": directory, "GITHUB_RUN_ID": "30", "GITHUB_RUN_ATTEMPT": "1", "NATIVE_JOB": json.dumps(job)}
            with patch.dict(os.environ, env):
                for token, attempt in (("foreign-token", "1"), ("synthetic-token-never-a-live-credential", "2")):
                    changed = json.loads(json.dumps(receipt)); changed["execution"]["attempt"] = int(attempt)
                    copy.grant_path().write_text(json.dumps(changed)); copy.grant_path().chmod(0o600)
                    with self.assertRaisesRegex(copy.archive.ControlError, "native-binding"):
                        copy.read_grant(token)
                    self.assertFalse(copy.grant_path().exists())
                with self.assertRaises(FileNotFoundError):
                    copy.read_grant("synthetic-token-never-a-live-credential")


if __name__ == "__main__":
    unittest.main()
