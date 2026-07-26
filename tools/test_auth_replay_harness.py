#!/usr/bin/env python3
"""Tests for tools/auth_replay_harness.py (per-role BOLA/BFLA replay engine).

The live-I/O seam `auth_replay_harness._http` is reassigned to a fake in each test,
so NO network is ever touched. Client-neutral throughout: synthetic roles
(client_user / admin), TEST-NET / example.test URLs, fake "tok-*" tokens.
"""
import unittest

import auth_replay_harness as H


def _resp(status, body):
    return {"status": status, "headers": {}, "body": body}


class ExtractTokenTest(unittest.TestCase):
    def test_nested_dotted_json_path(self):
        login = {"AuthenticationResult": {"AccessToken": "tok-nested", "IdToken": "tok-id"}}
        self.assertEqual(H.extract_token(login, "AuthenticationResult.AccessToken"), "tok-nested")

    def test_dotted_path_accepts_json_string(self):
        self.assertEqual(
            H.extract_token('{"a": {"b": "tok-str"}}', "a.b"), "tok-str")

    def test_storagestate_localstorage_key(self):
        storage = {
            "cookies": [],
            "origins": [{
                "origin": "https://app.example.test",
                "localStorage": [
                    {"name": "theme", "value": "dark"},
                    {"name": "access_token", "value": "tok-ls"},
                ],
            }],
        }
        self.assertEqual(H.extract_token(storage, "access_token"), "tok-ls")
        # dotted forms resolve on the final segment too
        self.assertEqual(H.extract_token(storage, "localStorage.access_token"), "tok-ls")

    def test_missing_paths_raise(self):
        with self.assertRaises(KeyError):
            H.extract_token({"a": {}}, "a.missing")
        with self.assertRaises(KeyError):
            H.extract_token({"origins": [{"localStorage": []}]}, "nope")

    def test_reachable_as_staticmethod(self):
        self.assertEqual(
            H.TokenStore.extract_token({"a": "tok-x"}, "a"), "tok-x")


class EvidenceIdTest(unittest.TestCase):
    def test_stable_deterministic_across_runs(self):
        a = H.evidence_id("R1", "client_user")
        b = H.evidence_id("R1", "client_user")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("ev-"))

    def test_distinct_inputs_distinct_ids(self):
        self.assertNotEqual(
            H.evidence_id("R1", "client_user"), H.evidence_id("R1", "admin"))
        self.assertNotEqual(
            H.evidence_id("R1", "client_user"), H.evidence_id("R2", "client_user"))

    def test_matrix_records_use_the_stable_id(self):
        store = H.TokenStore().add_role("client_user", "tok-clientuser")
        H._http = lambda *a, **k: _resp(403, "")
        try:
            res = H.replay_matrix([{"id": "R1", "url": "https://api.example.test/x"}], store)
        finally:
            H._http = ORIG_HTTP
        rec = res["records"][0]
        self.assertEqual(rec["evidence_id"], H.evidence_id("R1", "client_user"))


class ClassifyTest(unittest.TestCase):
    def test_verdicts(self):
        self.assertEqual(H.classify_response(200, '{"id": 1, "name": "a"}'), "authorized")
        self.assertEqual(H.classify_response(403, "forbidden"), "denied")
        self.assertEqual(H.classify_response(401, ""), "denied")
        self.assertEqual(H.classify_response(200, ""), "soft-denied")
        self.assertEqual(H.classify_response(200, '{"error": "nope"}'), "soft-denied")
        self.assertEqual(H.classify_response(200, '{"data": null}'), "soft-denied")
        self.assertEqual(H.classify_response(500, "boom"), "error")


class ReplayMatrixTest(unittest.TestCase):
    def setUp(self):
        self.store = (H.TokenStore()
                      .add_role("client_user", "tok-clientuser")
                      .add_role("victim_user", "tok-victim")
                      .add_role("admin", "tok-admin"))

    def tearDown(self):
        H._http = ORIG_HTTP

    def test_bola_flag_when_low_priv_reads_another_users_object(self):
        # victim owns acct-victim; the low-priv client_user token also gets 200+data.
        def fake(method, url, headers=None, body=None, proxy=None, timeout=30):
            auth = (headers or {}).get("Authorization", "")
            if "tok-victim" in auth or "tok-clientuser" in auth:
                return _resp(200, '{"account": "acct-victim", "balance": 42}')
            return _resp(403, "forbidden")
        H._http = fake
        res = H.replay_matrix([{
            "id": "GET-account", "method": "GET", "owner_role": "victim_user",
            "object_ref": "acct-victim",
            "url": "https://api.example.test/accounts/acct-victim",
        }], self.store)

        self.assertEqual(res["summary"]["authorized_cross_role"], 1)
        self.assertEqual(res["summary"]["bola_flags"], 1)
        self.assertEqual(res["summary"]["bfla_flags"], 0)
        self.assertEqual([f["as_role"] for f in res["flags"]], ["client_user"])
        self.assertEqual(res["flags"][0]["flag"], "bola")
        # owner authorized is NOT a finding
        owner_rec = next(r for r in res["records"] if r["as_role"] == "victim_user")
        self.assertEqual(owner_rec["verdict"], "authorized")
        self.assertIsNone(owner_rec["flag"])
        self.assertEqual(H._exit_code(res["summary"]), 1)

    def test_evidenced_negative_all_cross_role_denied(self):
        # Only the owner gets in; every other role is 403 -> no flags, exit 0.
        def fake(method, url, headers=None, body=None, proxy=None, timeout=30):
            auth = (headers or {}).get("Authorization", "")
            if "tok-victim" in auth:
                return _resp(200, '{"account": "acct-victim"}')
            return _resp(403, "forbidden")
        H._http = fake
        res = H.replay_matrix([{
            "id": "GET-account", "owner_role": "victim_user",
            "object_ref": "acct-victim",
            "url": "https://api.example.test/accounts/acct-victim",
        }], self.store)
        self.assertEqual(res["flags"], [])
        self.assertEqual(res["summary"]["authorized_cross_role"], 0)
        self.assertEqual(H._exit_code(res["summary"]), 0)
        # every cross-role verdict is a denial (the evidenced negative)
        cross = [r for r in res["records"] if r["cross_role"]]
        self.assertTrue(cross and all(r["verdict"] == "denied" for r in cross))

    def test_bfla_flag_privileged_action_from_low_priv(self):
        # A privileged action (no object_ref) that a low-priv role can invoke.
        def fake(method, url, headers=None, body=None, proxy=None, timeout=30):
            return _resp(200, '{"result": "promoted"}')  # server fails to gate it
        H._http = fake
        res = H.replay_matrix([{
            "id": "POST-promote", "method": "POST", "owner_role": "admin",
            "url": "https://api.example.test/admin/promote",
            "body": '{"user": "u1", "role": "admin"}',
        }], self.store)
        self.assertEqual(res["summary"]["bfla_flags"], 2)  # client_user + victim_user
        self.assertEqual(res["summary"]["bola_flags"], 0)
        self.assertTrue(all(f["flag"] == "bfla" for f in res["flags"]))
        self.assertEqual(H._exit_code(res["summary"]), 1)

    def test_allowed_roles_suppresses_the_flag(self):
        def fake(method, url, headers=None, body=None, proxy=None, timeout=30):
            return _resp(200, '{"data": [1, 2, 3]}')
        H._http = fake
        res = H.replay_matrix([{
            "id": "GET-report", "owner_role": "victim_user",
            "object_ref": "rpt-1", "allowed_roles": ["admin"],
            "url": "https://api.example.test/reports/rpt-1",
        }], self.store)
        # admin is explicitly allowed; only client_user remains a finding
        self.assertEqual([f["as_role"] for f in res["flags"]], ["client_user"])


class CrossTenantProbeTest(unittest.TestCase):
    def tearDown(self):
        H._http = ORIG_HTTP

    def test_tenant_a_token_reads_tenant_b_object(self):
        store = (H.TokenStore()
                 .add_role("tenantA_user", "tok-a", tenant="A")
                 .add_role("tenantB_user", "tok-b", tenant="B"))

        def fake(method, url, headers=None, body=None, proxy=None, timeout=30):
            auth = (headers or {}).get("Authorization", "")
            # The bug: tenant-A's token can read tenant-B's object.
            if "tok-a" in auth and "acct-b" in url:
                return _resp(200, '{"account": "acct-b", "owner": "tenantB"}')
            return _resp(403, "forbidden")
        H._http = fake
        res = H.cross_tenant_probe({
            "id": "GET-account", "method": "GET",
            "url": "https://api.example.test/accounts/{object_ref}",
            "objects_by_tenant": {"A": "acct-a", "B": "acct-b"},
        }, store)

        self.assertEqual(res["summary"]["cross_tenant_bola_flags"], 1)
        flag = res["flags"][0]
        self.assertEqual(flag["attacker_tenant"], "A")
        self.assertEqual(flag["target_tenant"], "B")
        self.assertEqual(flag["object_ref"], "acct-b")
        # deterministic evidence id for the directed pair
        self.assertEqual(flag["evidence_id"], H.evidence_id("GET-account", "A->B"))

    def test_isolated_tenants_no_flags(self):
        store = (H.TokenStore()
                 .add_role("tenantA_user", "tok-a", tenant="A")
                 .add_role("tenantB_user", "tok-b", tenant="B"))
        H._http = lambda *a, **k: _resp(403, "forbidden")
        res = H.cross_tenant_probe({
            "id": "GET-account",
            "url": "https://api.example.test/accounts/{object_ref}",
            "objects_by_tenant": {"A": "acct-a", "B": "acct-b"},
        }, store)
        self.assertEqual(res["flags"], [])
        self.assertEqual(res["summary"]["cross_tenant_bola_flags"], 0)


class BuildStoreTest(unittest.TestCase):
    def test_inline_token_and_extract_from_login(self):
        spec = {"roles": [
            {"role": "admin", "token": "tok-admin", "tenant": "A"},
            {"role": "client_user", "tenant": "A",
             "login_response": {"AuthenticationResult": {"AccessToken": "tok-cu"}},
             "token_path": "AuthenticationResult.AccessToken"},
        ]}
        store = H.build_store(spec)
        self.assertEqual(store.get("admin"), "tok-admin")
        self.assertEqual(store.get("client_user"), "tok-cu")
        self.assertEqual(store.roles(), ["admin", "client_user"])
        self.assertEqual(store.tenants(), ["A"])

    def test_token_env_resolution(self):
        import os
        os.environ["ARH_TEST_TOKEN"] = "tok-from-env"
        try:
            store = H.build_store({"roles": [{"role": "r", "token_env": "ARH_TEST_TOKEN"}]})
            self.assertEqual(store.get("r"), "tok-from-env")
        finally:
            del os.environ["ARH_TEST_TOKEN"]

    def test_missing_token_source_raises(self):
        with self.assertRaises(ValueError):
            H.build_store({"roles": [{"role": "r"}]})


class ValidateRequestsTest(unittest.TestCase):
    def test_accepts_bare_list_and_wrapping_object(self):
        good = [{"id": "R1", "method": "GET", "url": "https://api.example.test/x",
                 "owner_role": "victim_user", "object_ref": "acct-1"}]
        self.assertEqual(H.validate_requests(good), [])
        self.assertEqual(H.validate_requests({"requests": good}), [])

    def test_missing_id_and_url_reported(self):
        problems = H.validate_requests([{"method": "GET"}])
        self.assertTrue(any("missing 'id'" in p for p in problems))
        self.assertTrue(any("'url'" in p for p in problems))

    def test_object_body_rejected(self):
        problems = H.validate_requests([
            {"id": "R1", "url": "https://api.example.test/x", "body": {"k": "v"}}])
        self.assertTrue(any("'body' must be a string" in p for p in problems))

    def test_cross_tenant_requires_placeholder_and_objects(self):
        ok = {"cross_tenant": [{
            "id": "C1", "url": "https://api.example.test/a/{object_ref}",
            "objects_by_tenant": {"A": "a1", "B": "b1"}}]}
        self.assertEqual(H.validate_requests(ok), [])
        bad = {"cross_tenant": [{"id": "C1", "url": "https://api.example.test/a/fixed",
                                 "objects_by_tenant": {"A": "a1"}}]}
        self.assertTrue(any("{object_ref}" in p for p in H.validate_requests(bad)))

    def test_validated_shape_is_accepted_by_the_harness(self):
        # The contract guarantee fixture_ingest.py needs: a []-validating payload
        # replays without raising (HTTP seam faked, no network).
        payload = [{"id": "R1", "method": "GET", "owner_role": "victim_user",
                    "object_ref": "acct-1", "url": "https://api.example.test/accounts/acct-1"}]
        self.assertEqual(H.validate_requests(payload), [])
        store = H.TokenStore().add_role("victim_user", "tok-v").add_role("client_user", "tok-c")
        H._http = lambda *a, **k: _resp(403, "forbidden")
        try:
            res = H.replay_matrix(payload, store)
        finally:
            H._http = ORIG_HTTP
        self.assertEqual(res["summary"]["total"], 2)


class RunAndExitTest(unittest.TestCase):
    def tearDown(self):
        H._http = ORIG_HTTP

    def test_run_combines_matrix_and_cross_tenant(self):
        tokens = {"roles": [
            {"role": "client_user", "token": "tok-clientuser", "tenant": "A"},
            {"role": "tenantB_user", "token": "tok-b", "tenant": "B"},
        ]}
        requests = {
            "requests": [{
                "id": "GET-account", "owner_role": "tenantB_user",
                "object_ref": "acct-b",
                "url": "https://api.example.test/accounts/acct-b",
            }],
            "cross_tenant": [{
                "id": "GET-account",
                "url": "https://api.example.test/accounts/{object_ref}",
                "objects_by_tenant": {"A": "acct-a", "B": "acct-b"},
            }],
        }

        def fake(method, url, headers=None, body=None, proxy=None, timeout=30):
            auth = (headers or {}).get("Authorization", "")
            if "tok-clientuser" in auth and "acct-b" in url:
                return _resp(200, '{"account": "acct-b"}')
            return _resp(403, "forbidden")
        H._http = fake
        payload = H.run(requests, tokens)
        # one cross-role matrix BOLA + one cross-tenant BOLA both land in bola_flags
        self.assertEqual(payload["summary"]["bola_flags"], 2)
        self.assertEqual(payload["summary"]["cross_tenant_bola_flags"], 1)
        self.assertEqual(payload["summary"]["authorized_cross_role"], 2)
        self.assertEqual(H._exit_code(payload["summary"]), 1)


ORIG_HTTP = H._http


if __name__ == "__main__":
    unittest.main(verbosity=2)
