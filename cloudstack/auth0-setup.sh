#!/usr/bin/env bash
# Registers the Auth0 applications of the CloudStack sign-in gate ("cloudstack")
# and of Warpgate ("cloudstack-warpgate"), puts their client credentials into
# Vault, allows only the Google Workspace connection on them, and prints what
# the gate relies on: the groups claim of the post-login Action and the subject
# prefix of the Workspace connection's users. Prints no secret; safe to run
# again (existing applications are reused).
#
# Needs an Auth0 tenant administrator and a Vault login that may write
# secret/cloudstack/*:
#   nix shell nixpkgs#auth0-cli
#   auth0 login --scopes read:connections,update:connections
#   VAULT_ADDR=https://vault.bacchus.io vault login -method=oidc
#   bash cloudstack/auth0-setup.sh
# The Vault Secrets Operator picks the credentials up within five minutes and
# restarts the gate and Warpgate, which then open the Bacchus door.
set -euo pipefail
shopt -s inherit_errexit
export VAULT_ADDR=${VAULT_ADDR:-https://vault.bacchus.io}
CONNECTION=bacchus-workspace
py() { python3 -c "$1"; }

app() {  # app <name> <callback>: prints the client id, keeps the JSON in $tmp/<name>.json
  local name=$1 callback=$2 id
  id=$(auth0 apps list --json --number 1000 | py "import json,sys; print(next((a['client_id'] for a in json.load(sys.stdin) if a['name']=='$name'), ''))")
  if [ -z "$id" ]; then
    auth0 apps create --no-input --name "$name" --type regular --auth-method Basic \
      --description "SNUCSE Cloud sign-in ($name)" --callbacks "$callback" --reveal-secrets --json > "$tmp/$name.json"
    echo "created $name" >&2
  else
    auth0 apps update "$id" --no-input --callbacks "$callback" --auth-method Basic --json > /dev/null
    auth0 apps show "$id" --reveal-secrets --json > "$tmp/$name.json"
    echo "updated $name" >&2
  fi
  py "import json; print(json.load(open('$tmp/$name.json'))['client_id'])"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077

gate_id=$(app cloudstack https://cloud.snucse.org/gate/bacchus/callback)
wg_id=$(app cloudstack-warpgate https://login.cloud.snucse.org/@warpgate/api/sso/return)
echo "client ids: cloudstack=$gate_id cloudstack-warpgate=$wg_id"

# secrets go to Vault as JSON on stdin, never on a command line
py "import json; d=json.load(open('$tmp/cloudstack.json')); print(json.dumps({'client_id': d['client_id'], 'client_secret': d['client_secret']}))" |
  vault kv put -mount=secret cloudstack/oauth-bacchus - > /dev/null
echo "vault secret/cloudstack/oauth-bacchus: client_id, client_secret"
py "import json; d=json.load(open('$tmp/cloudstack-warpgate.json')); print(json.dumps({'bacchus_client_id': d['client_id'], 'bacchus_client_secret': d['client_secret']}))" |
  vault kv patch -mount=secret cloudstack/warpgate - > /dev/null
echo "vault secret/cloudstack/warpgate: + bacchus_client_id, bacchus_client_secret"

auth0 api get connections > "$tmp/connections.json"
py "import json; [print(c['id'], c['name'], c['strategy']) for c in json.load(open('$tmp/connections.json'))]" |
while read -r cid cname cstrategy; do
  status=false
  [ "$cname" = "$CONNECTION" ] && status=true
  auth0 api patch "connections/$cid/clients" \
    --data "[{\"client_id\":\"$gate_id\",\"status\":$status},{\"client_id\":\"$wg_id\",\"status\":$status}]" < /dev/null > /dev/null
  echo "connection $cname ($cstrategy): enabled=$status"
done

action=$(auth0 actions list --json | py "import json,sys; print(next((a['id'] for a in json.load(sys.stdin) if a['name']=='bacchus-access'), ''))")
if [ -n "$action" ]; then
  echo "action bacchus-access, lines about claims, clients and denials:"
  auth0 actions show "$action" --json | py "
import json, sys, re
code = json.load(sys.stdin).get('code', '')
for n, line in enumerate(code.splitlines(), 1):
    if re.search(r'setCustomClaim|client|deny|groups|bacchus\.io', line):
        print(f'  {n}: {line.strip()[:160]}')"
else
  echo "action bacchus-access: not found"
fi
auth0 users search --query "identities.connection:\"$CONNECTION\"" --number 1 --json |
  py "import json,sys; u=json.load(sys.stdin); print('user_id prefix of $CONNECTION users (gate.toml subject_prefix):', u[0]['user_id'].split('|')[0] + '|' if u else '(no user)')"
