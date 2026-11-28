"""Prometheus exporter of the VMs CloudStack has, for the guest metrics alerts
(cloudstack-monitoring/rules.yaml). One cloudstack_vm series per VM, labelled
with its UUID (what the guest's vmagent sends as instance_id), account,
project, state and whether its template ships vmagent (the tag sync.py puts on
those templates). It keeps nothing: every scrape asks CloudStack afresh, and
when CloudStack does not answer the scrape fails (503) instead of reporting no
VMs, so the alerts see the exporter down rather than every VM gone."""

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_URL = os.environ["CLOUDSTACK_API_URL"]
API_KEY = os.environ["CLOUDSTACK_API_KEY"].strip()
SECRET_KEY = os.environ["CLOUDSTACK_SECRET_KEY"].strip()
PORT = int(os.environ.get("EXPORTER_PORT", "9100"))
VMAGENT_TAG = ("vmagent", "true")  # sync.py's VMAGENT_TAG
LIST_PAGE_SIZE = 500  # default.page.size, the largest page the server accepts
METRICS_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def cloudstack(command, **params):
    """A signed GET of one API command (sync.py's, without POST)."""
    params.update(command=command, response="json", apikey=API_KEY)
    query = "&".join(
        f"{k}={urllib.parse.quote(str(v), safe='-_.*')}"
        for k, v in sorted(params.items(), key=lambda kv: kv[0].lower())
    )
    digest = hmac.new(SECRET_KEY.encode(), query.lower().encode(), hashlib.sha1).digest()
    signature = urllib.parse.quote(base64.b64encode(digest).decode(), safe="")
    with urllib.request.urlopen(f"{API_URL}?{query}&signature={signature}", timeout=20) as resp:
        body = json.load(resp)
    return body[f"{command.lower()}response"]


def cloudstack_list(command, key, **params):
    """Every item of a list command. Unpaged, the server returns only its first default.page.size items."""
    items, page = [], 1
    while True:
        batch = cloudstack(command, page=page, pagesize=LIST_PAGE_SIZE, **params).get(key, [])
        items += batch
        if len(batch) < LIST_PAGE_SIZE:
            return items
        page += 1


def vmagent_templates():
    """Ids of the templates tagged as shipping vmagent."""
    return {t["id"] for t in cloudstack_list("listTemplates", "template", templatefilter="all", listall="true")
            if any((tag.get("key"), tag.get("value")) == VMAGENT_TAG for tag in t.get("tags", []))}


def vms():
    """Every VM, project-owned ones included (they are only listed when asked for explicitly)."""
    found = cloudstack_list("listVirtualMachines", "virtualmachine", listall="true")
    found += cloudstack_list("listVirtualMachines", "virtualmachine", listall="true", projectid=-1)
    return list({vm["id"]: vm for vm in found}.values())


def label_value(value):
    # account and project names are chosen by users: escaped, they cannot end
    # the label or the line and so cannot add series of their own
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(vms, templates):
    lines = [
        "# HELP cloudstack_vm A VM CloudStack has; vmagent=true if its template ships vmagent.",
        "# TYPE cloudstack_vm gauge",
    ]
    for vm in sorted(vms, key=lambda v: v["id"]):
        labels = {
            "instance_id": vm["id"],
            "account": vm.get("account", ""),
            "project": vm.get("project", ""),
            "state": vm.get("state", ""),
            "vmagent": "true" if vm.get("templateid") in templates else "false",
        }
        lines.append("cloudstack_vm{" + ",".join(f'{k}="{label_value(v)}"' for k, v in labels.items()) + "} 1")
    return "\n".join(lines) + "\n"


def scrape():
    """The /metrics body, or None when CloudStack did not answer."""
    try:
        return render(vms(), vmagent_templates())
    except Exception as e:  # noqa: BLE001 - any failure is a failed scrape
        # the type and message only: a request URL would carry the API key
        print(f"scrape failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":  # never calls CloudStack, so it stays up while CloudStack is down
            self.reply(200, "ok\n")
        elif path == "/metrics":
            body = scrape()
            if body is None:
                self.reply(503, "CloudStack did not answer\n")
            else:
                self.reply(200, body, METRICS_TYPE)
        else:
            self.reply(404, "not found\n")

    def reply(self, status, body, content_type="text/plain; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # one line per scrape and probe is noise
        pass


def main():
    server = ThreadingHTTPServer(("", PORT), Handler)
    print(f"listening on :{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
