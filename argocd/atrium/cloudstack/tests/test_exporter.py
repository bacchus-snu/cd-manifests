import importlib
import json
import os
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

os.environ.setdefault("CLOUDSTACK_API_URL", "http://cloudstack.test/client/api")
os.environ.setdefault("CLOUDSTACK_API_KEY", "k")
os.environ.setdefault("CLOUDSTACK_SECRET_KEY", "s")
exporter = importlib.import_module("exporter")
sync = importlib.import_module("sync")


class FakeCloudStack:
    def __init__(self, vms=(), project_vms=(), templates=()):
        self.vms, self.project_vms, self.templates = list(vms), list(project_vms), list(templates)
        self.calls = []

    def __call__(self, command, **params):
        self.calls.append((command, params))
        if command == "listVirtualMachines":
            items = self.project_vms if params.get("projectid") == -1 else self.vms
            key = "virtualmachine"
        elif command == "listTemplates":
            items, key = self.templates, "template"
        else:
            raise AssertionError(f"unexpected command {command}")
        size, page = params["pagesize"], params["page"]
        return {key: items[(page - 1) * size:page * size]}


class RenderTest(unittest.TestCase):
    def series(self, text):
        return [line for line in text.splitlines() if not line.startswith("#")]

    def test_one_series_per_vm_marked_by_its_template(self):
        vms = [
            {"id": "b-2", "account": "bob", "state": "Stopped", "templateid": "t-plain"},
            {"id": "a-1", "account": "alice", "state": "Running", "templateid": "t-gpu"},
        ]
        self.assertEqual(self.series(exporter.render(vms, {"t-gpu"})), [
            'cloudstack_vm{instance_id="a-1",account="alice",project="",state="Running",vmagent="true"} 1',
            'cloudstack_vm{instance_id="b-2",account="bob",project="",state="Stopped",vmagent="false"} 1',
        ])

    def test_user_chosen_names_cannot_add_series(self):
        vm = {"id": "a-1", "account": "x", "project": 'p"} 1\ncloudstack_vm{instance_id="forged', "state": "Running"}
        series = self.series(exporter.render([vm], set()))
        self.assertEqual(len(series), 1)
        self.assertIn('project="p\\"} 1\\ncloudstack_vm{instance_id=\\"forged"', series[0])

    def test_backslashes_are_escaped_first(self):
        self.assertEqual(exporter.label_value('a\\"b'), 'a\\\\\\"b')

    def test_no_vms_is_an_empty_but_valid_page(self):
        self.assertEqual(self.series(exporter.render([], set())), [])


class CloudStackTest(unittest.TestCase):
    def test_every_page_and_project_vms_are_listed_once(self):
        size = exporter.LIST_PAGE_SIZE
        own = [{"id": f"vm-{i}"} for i in range(size + 3)]
        project = [{"id": "vm-p"}, {"id": "vm-0"}]  # an id seen in both lists counts once
        fake = FakeCloudStack(vms=own, project_vms=project)
        with mock.patch.object(exporter, "cloudstack", fake):
            ids = [vm["id"] for vm in exporter.vms()]
        self.assertEqual(len(ids), size + 4)
        self.assertEqual(len(set(ids)), len(ids))
        self.assertIn("vm-p", ids)
        self.assertTrue(all(p["listall"] == "true" for c, p in fake.calls))

    def test_only_templates_with_the_tag_count(self):
        fake = FakeCloudStack(templates=[
            {"id": "t-gpu", "tags": [{"key": "vmagent", "value": "true"}]},
            {"id": "t-other", "tags": [{"key": "vmagent", "value": "false"}, {"key": "x", "value": "true"}]},
            {"id": "t-plain"},
        ])
        with mock.patch.object(exporter, "cloudstack", fake):
            self.assertEqual(exporter.vmagent_templates(), {"t-gpu"})
        self.assertEqual(fake.calls[0][1]["templatefilter"], "all")

    def test_the_tag_is_the_one_sync_puts_on(self):
        self.assertEqual(exporter.VMAGENT_TAG, sync.VMAGENT_TAG)

    def test_requests_are_signed_gets(self):
        seen = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return json.dumps({"listzonesresponse": {"zone": []}}).encode()

        def urlopen(url, timeout):
            seen.append(url)
            return Response()
        with mock.patch.object(exporter.urllib.request, "urlopen", urlopen):
            self.assertEqual(exporter.cloudstack("listZones"), {"zone": []})
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(seen[0]).query)
        self.assertEqual(query["apikey"], [exporter.API_KEY])
        self.assertIn("signature", query)
        # the same signature sync.py makes for the same request
        with mock.patch.object(sync.urllib.request, "urlopen", urlopen):
            sync.cloudstack("listZones")
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(seen[1]).query)["signature"], query["signature"])


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), exporter.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as resp:
                return resp.status, resp.headers.get("Content-Type"), resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type"), e.read().decode()

    def test_metrics(self):
        fake = FakeCloudStack(vms=[{"id": "a-1", "account": "alice", "state": "Running", "templateid": "t-gpu"}],
                              templates=[{"id": "t-gpu", "tags": [{"key": "vmagent", "value": "true"}]}])
        with mock.patch.object(exporter, "cloudstack", fake):
            status, content_type, body = self.get("/metrics")
        self.assertEqual(status, 200)
        self.assertTrue(content_type.startswith("text/plain; version=0.0.4"))
        self.assertIn('instance_id="a-1"', body)
        self.assertIn('vmagent="true"', body)

    def test_cloudstack_down_fails_the_scrape(self):
        def down(command, **params):
            raise urllib.error.URLError("connection refused")
        with mock.patch.object(exporter, "cloudstack", down), mock.patch("sys.stderr"):
            status, _, body = self.get("/metrics")
        self.assertEqual(status, 503)
        self.assertNotIn("cloudstack_vm", body)

    def test_healthz_does_not_ask_cloudstack(self):
        def down(command, **params):
            raise AssertionError("called CloudStack")
        with mock.patch.object(exporter, "cloudstack", down):
            self.assertEqual(self.get("/healthz")[0], 200)

    def test_other_paths_are_not_found(self):
        self.assertEqual(self.get("/")[0], 404)
        self.assertEqual(self.get("/metrics/x")[0], 404)


if __name__ == "__main__":
    unittest.main()
