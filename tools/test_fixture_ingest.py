#!/usr/bin/env python3
"""Tests for tools/fixture_ingest.py (corpus -> auth_replay_harness request-templates).

Deterministic, in-code fixtures only. Run: ``python3 tools/test_fixture_ingest.py``.
Client-neutral throughout (example.test hosts, placeholder ids).
"""
import importlib
import io
import json
import os
import tempfile
import unittest

import fixture_ingest as m


# --- shared fixtures ---------------------------------------------------------
def _openapi():
    return {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v1"}],
        "paths": {
            "/users/{id}": {"get": {
                "operationId": "getUserById",
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "integer"}}]}},
            "/accounts": {"post": {
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object", "required": ["name", "balance"],
                    "properties": {"name": {"type": "string"},
                                   "balance": {"type": "integer"}}}}}}}},
        },
    }


def _postman():
    return {
        "info": {"schema": "https://schema.getpostman.com/json/collection/"
                           "v2.1.0/collection.json"},
        "variable": [{"key": "baseUrl", "value": "https://placeholder.invalid"}],
        "item": [{"name": "grp", "item": [
            {"name": "getUser", "request": {
                "method": "GET", "url": "{{baseUrl}}/users/42",
                "header": [{"key": "Authorization", "value": "Bearer SECRET-TOKEN"},
                           {"key": "Accept", "value": "application/json"}]}},
            {"name": "createOrder", "request": {
                "method": "POST", "url": "{{baseUrl}}/orders",
                "body": {"mode": "urlencoded",
                         "urlencoded": [{"key": "sku", "value": "abc"}]}}},
        ]}],
    }


def _har():
    return {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://api.example.test/items/7?x=1",
                     "headers": [{"name": "Cookie", "value": "sid=SECRET"},
                                 {"name": "Accept", "value": "*/*"}]}},
        {"request": {"method": "GET", "url": "https://api.example.test/items/7?x=2",
                     "headers": [{"name": "Accept", "value": "*/*"}]}},
        {"request": {"method": "POST", "url": "https://api.example.test/login",
                     "postData": {"mimeType": "application/json",
                                  "text": "{\"u\":\"a\"}"}}},
    ]}}


def _by_id(templates):
    return {t["id"]: t for t in templates}


# ---------------------------------------------------------------------------
class OpenApiTest(unittest.TestCase):
    def test_path_filled_object_ref_and_body_sampled(self):
        r = m.ingest(_openapi())
        t = _by_id(r["templates"])
        get = t["getUserById"]
        # servers[0].url used as base; {id} placeholder filled with a typed value
        self.assertEqual(get["url"], "https://api.example.test/v1/users/1")
        self.assertEqual(get["method"], "GET")
        # id path param classified as an object_ref (BOLA candidate)
        self.assertEqual(get["object_ref"], {"in": "path", "name": "id", "value": "1"})
        # POST body sampled from required schema props, serialized to a JSON string
        # (the harness requires a string body it can put on the wire)
        post = t["POST_/accounts"]
        self.assertEqual(post["url"], "https://api.example.test/v1/accounts")
        self.assertIsInstance(post["body"], str)
        self.assertEqual(json.loads(post["body"]), {"name": "test", "balance": 1})

    def test_base_url_override(self):
        r = m.ingest(_openapi(), base_url="https://alt.example.test/api/")
        self.assertEqual(_by_id(r["templates"])["getUserById"]["url"],
                         "https://alt.example.test/api/users/1")

    def test_swagger2_base_from_host_basepath_schemes(self):
        doc = {"swagger": "2.0", "host": "svc.example.test", "basePath": "/v2",
               "schemes": ["https"],
               "paths": {"/ping": {"get": {"operationId": "ping"}}}}
        r = m.ingest(doc)
        self.assertEqual(_by_id(r["templates"])["ping"]["url"],
                         "https://svc.example.test/v2/ping")

    def test_security_public_vs_required_vs_unknown(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "security": [{"apiKey": []}],
               "paths": {
                   "/pub": {"get": {"operationId": "pub", "security": []}},
                   "/priv": {"get": {"operationId": "priv"}},   # inherits global
                   "/exp": {"get": {"operationId": "exp", "security": [{"oauth": []}]}}}}
        t = _by_id(m.ingest(doc)["templates"])
        self.assertEqual(t["pub"]["auth"], "public")
        self.assertEqual(t["priv"]["auth"], "required")
        self.assertEqual(t["exp"]["auth"], "required")

    def test_unknown_auth_when_no_security_anywhere(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/x": {"get": {"operationId": "x"}}}}
        self.assertEqual(_by_id(m.ingest(doc)["templates"])["x"]["auth"], "unknown")

    def test_role_hint_from_extension(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/admin": {"get": {"operationId": "adminOp",
                                            "x-required-role": "admin"}}}}
        self.assertEqual(_by_id(m.ingest(doc)["templates"])["adminOp"]["owner_role"],
                         "admin")

    def test_required_query_param_appended(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/search": {"get": {"operationId": "search", "parameters": [
                   {"name": "q", "in": "query", "required": True,
                    "schema": {"type": "string"}},
                   {"name": "page", "in": "query", "schema": {"type": "integer"}}]}}}}
        url = _by_id(m.ingest(doc)["templates"])["search"]["url"]
        self.assertIn("q=test", url)
        self.assertNotIn("page", url)  # optional query params are not forced

    def test_uuid_path_param_is_object_ref_with_placeholder(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/orders/{orderUuid}": {"get": {"operationId": "getOrder",
                   "parameters": [{"name": "orderUuid", "in": "path", "required": True,
                                   "schema": {"type": "string", "format": "uuid"}}]}}}}
        t = _by_id(m.ingest(doc)["templates"])["getOrder"]
        self.assertEqual(t["object_ref"]["value"], m._UUID_PLACEHOLDER)
        self.assertIn(m._UUID_PLACEHOLDER, t["url"])

    def test_body_ref_resolution(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "components": {"schemas": {"Acct": {
                   "type": "object", "required": ["name"],
                   "properties": {"name": {"type": "string"}}}}},
               "paths": {"/a": {"post": {"operationId": "mk", "requestBody": {
                   "content": {"application/json": {"schema": {
                       "$ref": "#/components/schemas/Acct"}}}}}}}}
        self.assertEqual(json.loads(_by_id(m.ingest(doc)["templates"])["mk"]["body"]),
                         {"name": "test"})

    def test_degenerate_spec_undeclared_params_and_no_body(self):
        # Minimal/degenerate spec: an undeclared {id} path param and an op with no
        # requestBody. Regression for three bugs: unfilled placeholder, missing
        # object_ref, and a (body, content_type) tuple leaking into body.
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://api.example.test"}],
               "paths": {
                   "/users/{id}": {"get": {"operationId": "getUser",
                                           "security": [{"bearer": []}]}},
                   "/accounts": {"post": {"operationId": "createAccount"}}}}
        r = m.ingest(doc)
        t = _by_id(r["templates"])
        get, post = t["getUser"], t["createAccount"]
        # bug 1: no body on the GET, and no non-string body anywhere
        self.assertNotIn("body", get)
        self.assertNotIn("body", post)
        for tmpl in r["templates"]:
            self.assertNotIsInstance(tmpl.get("body"), (list, tuple, dict))
        # bug 2: the undeclared {id} placeholder was filled
        self.assertEqual(get["url"], "https://api.example.test/users/1")
        self.assertNotIn("{id}", get["url"])
        # bug 3: id-like undeclared placeholder marked as an object_ref
        self.assertEqual(get["object_ref"], {"in": "path", "name": "id", "value": "1"})
        self.assertEqual(r["stats"]["object_ref_count"], 1)
        # the harness accepts the degenerate output verbatim
        try:
            harness = importlib.import_module("auth_replay_harness")
        except Exception as exc:
            self.skipTest("auth_replay_harness not importable yet: %s" % exc)
        self.assertEqual(harness.validate_requests(r["templates"]), [])

    def test_get_with_spec_body_drops_the_body(self):
        # A GET that (invalidly) declares a requestBody must NOT carry a body.
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/x": {"get": {"operationId": "g", "requestBody": {
                   "content": {"application/json": {"schema": {
                       "type": "object", "required": ["a"],
                       "properties": {"a": {"type": "string"}}}}}}}}}}
        self.assertNotIn("body", _by_id(m.ingest(doc)["templates"])["g"])

    def test_multiple_undeclared_placeholders_all_filled(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/orgs/{orgUuid}/users/{userId}": {
                   "get": {"operationId": "nested"}}}}
        t = _by_id(m.ingest(doc)["templates"])["nested"]
        self.assertNotIn("{", t["url"])
        # first id-like token wins as the object_ref (the uuid here)
        self.assertEqual(t["object_ref"]["name"], "orgUuid")
        self.assertEqual(t["object_ref"]["value"], m._UUID_PLACEHOLDER)

    def test_json_body_sets_content_type_header(self):
        # the harness reads Content-Type only from headers, so a serialized JSON
        # body must carry its media type there
        post = _by_id(m.ingest(_openapi())["templates"])["POST_/accounts"]
        self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_path_level_params_merged_into_operation(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://a.example.test"}],
               "paths": {"/u/{id}": {
                   "parameters": [{"name": "id", "in": "path", "required": True,
                                   "schema": {"type": "integer"}}],
                   "get": {"operationId": "g"}}}}
        t = _by_id(m.ingest(doc)["templates"])["g"]
        self.assertEqual(t["url"], "https://a.example.test/u/1")
        self.assertEqual(t["object_ref"]["name"], "id")


class PostmanTest(unittest.TestCase):
    def test_baseurl_resolved_from_variables_and_auth_stripped(self):
        r = m.ingest(_postman(), kind="postman",
                     variables={"baseUrl": "https://api.example.test"})
        t = _by_id(r["templates"])
        # {{baseUrl}} resolved from the passed variables dict (overrides collection var)
        self.assertEqual(t["getUser"]["url"], "https://api.example.test/users/42")
        # Authorization header STRIPPED, kept out of headers, recorded in warnings
        self.assertNotIn("Authorization", t["getUser"].get("headers", {}))
        self.assertEqual(t["getUser"]["headers"], {"Accept": "application/json"})
        self.assertTrue(any("stripped auth header 'Authorization'" in w
                            for w in r["warnings"]))
        # object_ref inferred from the concrete numeric segment
        self.assertEqual(t["getUser"]["object_ref"], {"in": "path", "value": "42"})

    def test_urlencoded_body_and_folder_recursion(self):
        r = m.ingest(_postman(), kind="postman",
                     variables={"baseUrl": "https://api.example.test"})
        t = _by_id(r["templates"])
        # nested folder item was reached; urlencoded body serialized to a string
        self.assertEqual(t["createOrder"]["body"], "sku=abc")

    def test_unresolved_variable_warns_and_left_placeholder(self):
        coll = {"info": {"schema": "postman"}, "item": [
            {"name": "x", "request": {"method": "GET", "url": "{{missing}}/z"}}]}
        r = m.ingest(coll, kind="postman")
        self.assertIn("{{missing}}", _by_id(r["templates"])["x"]["url"])
        self.assertTrue(any("unresolved variable {{missing}}" in w
                            for w in r["warnings"]))

    def test_shorthand_string_request(self):
        coll = {"info": {"schema": "postman"}, "item": [
            {"name": "s", "request": "https://api.example.test/health"}]}
        t = _by_id(m.ingest(coll, kind="postman")["templates"])["s"]
        self.assertEqual(t["method"], "GET")
        self.assertEqual(t["url"], "https://api.example.test/health")


class HarTest(unittest.TestCase):
    def test_dedup_identical_method_path_with_count(self):
        r = m.ingest(_har())
        self.assertEqual(r["stats"]["total"], 2)  # the two /items/7 collapsed
        items = [t for t in r["templates"] if t["method"] == "GET"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["count"], 2)
        # first-seen URL (with its query) retained
        self.assertEqual(items[0]["url"], "https://api.example.test/items/7?x=1")

    def test_strips_auth_cookie_header(self):
        r = m.ingest(_har())
        get = [t for t in r["templates"] if t["method"] == "GET"][0]
        self.assertEqual(get.get("headers"), {"Accept": "*/*"})
        self.assertTrue(any("stripped auth header 'Cookie'" in w
                            for w in r["warnings"]))

    def test_body_carried_from_postdata(self):
        r = m.ingest(_har())
        post = [t for t in r["templates"] if t["method"] == "POST"][0]
        self.assertEqual(post["body"], "{\"u\":\"a\"}")
        # postData.mimeType propagated to a Content-Type header
        self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_existing_content_type_header_not_overridden(self):
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://api.example.test/x",
                         "headers": [{"name": "Content-Type", "value": "text/xml"}],
                         "postData": {"mimeType": "application/json",
                                      "text": "<a/>"}}}]}}
        t = m.ingest(har)["templates"][0]
        self.assertEqual(t["headers"]["Content-Type"], "text/xml")


class DetectAndDispatchTest(unittest.TestCase):
    def test_detect_each_kind(self):
        self.assertEqual(m.detect_kind(_openapi()), "openapi")
        self.assertEqual(m.detect_kind(_postman()), "postman")
        self.assertEqual(m.detect_kind(_har()), "har")
        self.assertIsNone(m.detect_kind({"foo": "bar"}))

    def test_auto_dispatch_routes_correctly(self):
        self.assertTrue(_by_id(m.ingest(_openapi(), kind="auto")["templates"]))
        self.assertIn("getUser", _by_id(m.ingest(
            _postman(), kind="auto",
            variables={"baseUrl": "https://api.example.test"})["templates"]))
        self.assertEqual(m.ingest(_har(), kind="auto")["stats"]["total"], 2)

    def test_undetectable_kind_raises(self):
        with self.assertRaises(m.UnparseableError):
            m.ingest({"foo": "bar"}, kind="auto")


class StatsAndSecretsTest(unittest.TestCase):
    def test_stats_shape(self):
        s = m.ingest(_openapi())["stats"]
        self.assertEqual(set(s), {"total", "by_method", "object_ref_count",
                                  "public", "authed"})
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["by_method"], {"GET": 1, "POST": 1})
        self.assertEqual(s["object_ref_count"], 1)

    def test_every_body_is_a_string(self):
        # The harness requires body to be a string it can put on the wire.
        for src, kw in ((_openapi(), {}),
                        (_postman(), {"kind": "postman",
                                      "variables": {"baseUrl": "https://x.example.test"}}),
                        (_har(), {})):
            for t in m.ingest(src, **kw)["templates"]:
                if "body" in t:
                    self.assertIsInstance(t["body"], str, "body must be str: %r" % t)

    def test_no_secret_ever_reaches_a_template(self):
        # every source carries a bearer/cookie secret; none may survive
        for src, kw in ((_postman(), {"kind": "postman",
                                      "variables": {"baseUrl": "https://x.example.test"}}),
                        (_har(), {})):
            blob = json.dumps(m.ingest(src, **kw)["templates"])
            self.assertNotIn("SECRET", blob)
            self.assertNotIn("Authorization", blob)


class LoaderTest(unittest.TestCase):
    def test_json_file_path_loads(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(_openapi(), f)
            path = f.name
        try:
            self.assertEqual(m.ingest(path)["stats"]["total"], 2)
        finally:
            os.unlink(path)

    def test_yaml_without_pyyaml_degrades(self):
        # simulate pyyaml being unavailable; a .yaml source must warn + degrade,
        # never crash.
        saved = m._yaml
        m._yaml = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
                f.write("openapi: 3.0.0\npaths: {}\n")
                path = f.name
            try:
                r = m.ingest(path)
                self.assertEqual(r["templates"], [])
                self.assertTrue(any("pyyaml" in w for w in r["warnings"]))
            finally:
                os.unlink(path)
        finally:
            m._yaml = saved

    def test_non_object_source_raises(self):
        with self.assertRaises(m.UnparseableError):
            m.ingest(12345)


class CliTest(unittest.TestCase):
    def _capture(self, argv):
        import contextlib
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = m.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_cli_stdout_json_ok(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(_openapi(), f)
            path = f.name
        try:
            code, out, _ = self._capture([path, "--json"])
            self.assertEqual(code, 0)
            doc = json.loads(out)
            # the CLI doc is the harness --requests input: templates under `requests`
            self.assertIn("requests", doc)
            self.assertEqual(len(doc["requests"]), 2)
            self.assertEqual(doc["stats"]["total"], 2)
        finally:
            os.unlink(path)

    def test_cli_writes_out_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(_har(), f)
            src = f.name
        dst = src + ".out.json"
        try:
            code, _, _ = self._capture([src, "-o", dst])
            self.assertEqual(code, 0)
            with open(dst) as fh:
                self.assertEqual(json.load(fh)["stats"]["total"], 2)
        finally:
            os.unlink(src)
            if os.path.exists(dst):
                os.unlink(dst)

    def test_cli_unparseable_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"foo": "bar"}, f)
            path = f.name
        try:
            code, _, err = self._capture([path])
            self.assertEqual(code, 2)
            self.assertIn("detect", err)
        finally:
            os.unlink(path)

    def test_cli_bad_vars_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(_postman(), f)
            path = f.name
        try:
            code, _, err = self._capture([path, "--vars", "not-json"])
            self.assertEqual(code, 2)
            self.assertIn("vars", err)
        finally:
            os.unlink(path)


class HarnessContractTest(unittest.TestCase):
    """The emitted templates must be a valid auth_replay_harness --requests input.

    A deterministic structural check always runs. When auth_replay_harness is
    importable it is additionally fed the templates with the HTTP seam faked, so
    the two tools stay wire-compatible as the harness lands.
    """

    REQUIRED = {"id", "method", "url"}
    ALLOWED = REQUIRED | {"headers", "body", "owner_role", "object_ref",
                          "auth", "count"}

    def _all_templates(self):
        out = []
        out += m.ingest(_openapi())["templates"]
        out += m.ingest(_postman(), kind="postman",
                        variables={"baseUrl": "https://api.example.test"})["templates"]
        out += m.ingest(_har())["templates"]
        return out

    def test_templates_conform_to_request_shape(self):
        for t in self._all_templates():
            self.assertTrue(self.REQUIRED <= set(t), "missing required keys: %r" % t)
            self.assertTrue(set(t) <= self.ALLOWED, "unexpected keys: %r" % t)
            self.assertIsInstance(t["id"], str)
            self.assertIsInstance(t["method"], str)
            self.assertTrue(t["url"].startswith("http"))
            if "headers" in t:
                self.assertIsInstance(t["headers"], dict)

    def test_harness_validates_and_replays_our_output(self):
        try:
            harness = importlib.import_module("auth_replay_harness")
        except Exception as exc:  # harness built in parallel; skip until it lands
            self.skipTest("auth_replay_harness not importable yet: %s" % exc)
        templates = self._all_templates()

        # 1) The harness's own producer-test hook accepts our shape, both forms:
        #    the bare list (ingest() `templates`) AND the CLI doc (list under
        #    `requests`, the key its _split_requests reads).
        self.assertEqual(harness.validate_requests(templates), [])
        cli_doc = {"requests": templates, "stats": {}, "warnings": []}
        self.assertEqual(harness.validate_requests(cli_doc), [])

        # 2) End-to-end: replay_matrix consumes the templates with the HTTP seam
        #    faked (no network), producing one record per (request x role).
        saved = harness._http
        harness._http = lambda *a, **k: {"status": 403, "headers": {}, "body": ""}
        try:
            store = harness.build_store(
                {"roles": [{"role": "user", "token": "t1"},
                           {"role": "admin", "token": "t2"}]})
            result = harness.replay_matrix(templates, store)
        finally:
            harness._http = saved
        self.assertEqual(result["summary"]["total"], len(templates) * 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
