#!/usr/bin/env bash
# provision_vantage.sh — the mandatory wrapper for spinning up an ephemeral cloud
# VM to attack FROM (and for tearing it back down). It creates the instance, reads
# its public IP, and registers that IP as an `attack-vm` source vantage via
# tools/register_source_ip.py, so the engagement's source-ips.jsonl (and the report
# appendix) always account for every attacking IP. ALWAYS provision/decommission
# attack infrastructure through this wrapper — a raw `gcloud/aws/az create` is only
# caught best-effort by the activity-logger hook.
#
# Usage:
#   # create (default mode)
#   tools/provision_vantage.sh --provider gcp|aws|az --region <r> \
#       [--name <instance-name>] [--engagement <root>] [--ssh-ready] [--dry-run] [-- <extra create args>]
#   # tear ONE VM down by its handle (provider:zone-or-region:name-or-iid)
#   tools/provision_vantage.sh --teardown <handle> [--engagement <root>] [--dry-run]
#   # idempotent GC of every VM labelled engagement=<id> (self-heals a prior crash)
#   tools/provision_vantage.sh --reap --engagement <root> [--dry-run]
#
# EPHEMERALITY GUARANTEES (a JS finally / shell trap alone leaks a public VM on
# SIGKILL): every created VM carries a `engagement=<id>` label AND a provider-native
# max-run-duration (gcp: --max-run-duration + --instance-termination-action=DELETE,
# default 2h via PROVISION_TTL_SECONDS) so it self-deletes even if the run is killed;
# --reap cleans orphans; --teardown removes a specific VM. "Deregister" is an APPENDED
# role:decommissioned line — the source-ips.jsonl ledger is append-only, never mutated.
#
# --dry-run     : do NOT touch any provider; emit a synthetic IP + handle (create) or a
#                 `torn-down`/`reaped` line, and STILL append the ledger line. This is
#                 the committed test path (tools/test_provision_vantage.sh).
# --engagement  : engagement root; defaults to the path in .claude/state/active-engagement.
# --ssh-ready   : after create, block until SSH answers (best-effort, gcp).
#
# Provider-specific inputs come from env vars (documented defaults below):
#   gcp: PROVISION_GCP_MACHINE (e2-small)  PROVISION_GCP_IMAGE_FAMILY (debian-12)
#        PROVISION_GCP_IMAGE_PROJECT (debian-cloud)   [--region is used as the ZONE]
#   aws: PROVISION_AWS_AMI (required)  PROVISION_AWS_TYPE (t3.small)
#   az : PROVISION_AZ_RG (required)   PROVISION_AZ_IMAGE (Ubuntu2204)
#   all: PROVISION_TTL_SECONDS (7200) — VM max lifetime / crash backstop.
#        PROVISION_SSH_SRC — if set, scope an SSH-ingress firewall rule to this CIDR (gcp).
#
# Real VM creation is not CI-testable; the --dry-run paths (create/teardown/reap) are
# exercised by tools/test_provision_vantage.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

provider=""; region=""; name=""; engagement=""; dry_run=0; extra=()
mode="create"; teardown_handle=""; ssh_ready=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider) provider="$2"; shift 2;;
    --region)   region="$2"; shift 2;;
    --name)     name="$2"; shift 2;;
    --engagement) engagement="$2"; shift 2;;
    --dry-run)  dry_run=1; shift;;
    --teardown) mode="teardown"; teardown_handle="$2"; shift 2;;
    --reap)     mode="reap"; shift;;
    --ssh-ready) ssh_ready=1; shift;;
    --) shift; extra=("$@"); break;;
    *) echo "provision_vantage: unknown arg: $1" >&2; exit 2;;
  esac
done

# Resolve engagement root (arg wins, else the active-engagement pointer).
if [[ -z "$engagement" ]]; then
  ptr="$REPO_ROOT/.claude/state/active-engagement"
  [[ -f "$ptr" ]] && engagement="$(cat "$ptr" 2>/dev/null || true)"
fi
[[ -n "$engagement" ]] || { echo "provision_vantage: no --engagement and no active-engagement pointer" >&2; exit 2; }

# engagement label: sanitized basename (gcp label = lowercase alnum + hyphen, <=63).
eng_id="$(basename "$engagement" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | cut -c1-40)"

register() {  # register <ip> [role] [note]
  python3 "$REPO_ROOT/tools/register_source_ip.py" "$1" \
    --role "${2:-attack-vm}" --provider "$provider" --region "$region" \
    --note "${3:-provision_vantage ${name}}" --engagement "$engagement"
}

# verify_egress <ip> — prove the VM actually egresses from <ip> by echoing it
# FROM the VM, then hand the raw output to verify_source_ip.py. Registration
# alone is only intent (verified:false); this is what makes the vantage count
# toward coverage_gate's min_vantages. Best-effort: a failed verification leaves
# the vantage usable-but-unverified and never aborts provisioning.
verify_egress() {
  local vip="$1" echo_out=""
  case "$provider" in
    gcp) echo_out="$(gcloud compute ssh "$name" --zone "$region" \
                       --command "curl -s --max-time 10 ifconfig.me || curl -s --max-time 10 https://api.ipify.org" \
                       2>/dev/null || true)" ;;
    *)   return 0 ;;   # aws/az have no uniform exec channel here; verify from the caller
  esac
  [[ -n "$echo_out" ]] || { echo "provision_vantage: egress echo empty; vantage stays unverified" >&2; return 0; }
  printf '%s\n' "$echo_out" | python3 "$REPO_ROOT/tools/verify_source_ip.py" \
    --ip "$vip" --role attack-vm --provider "$provider" --region "$region" \
    --note "egress echo from ${name}" --evidence-file - --engagement "$engagement" \
    >&2 || echo "provision_vantage: egress echo did not confirm ${vip}; vantage stays unverified" >&2
  return 0
}

# ---------------------------------------------------------------------------
# teardown: delete ONE VM by handle + append a role:decommissioned ledger line.
# ---------------------------------------------------------------------------
if [[ "$mode" == "teardown" ]]; then
  [[ -n "$teardown_handle" ]] || { echo "provision_vantage: --teardown needs a handle" >&2; exit 2; }
  IFS=':' read -r t_prov t_loc t_name <<<"$teardown_handle"
  provider="$t_prov"; region="$t_loc"
  if [[ "$dry_run" -eq 1 || "$t_prov" == dry-run* ]]; then
    register "203.0.113.7" decommissioned "torn down ${teardown_handle}"
    echo "torn-down ${teardown_handle}"; exit 0
  fi
  t_ip=""
  case "$t_prov" in
    gcp) t_ip="$(gcloud compute instances describe "$t_name" --zone "$t_loc" --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)"
         gcloud compute instances delete "$t_name" --zone "$t_loc" --quiet >&2 || true ;;
    aws) t_ip="$(aws ec2 describe-instances --region "$t_loc" --instance-ids "$t_name" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || true)"
         aws ec2 terminate-instances --region "$t_loc" --instance-ids "$t_name" >&2 || true ;;
    az)  az vm delete --resource-group "$t_loc" --name "$t_name" --yes >&2 || true ;;
    *)   echo "provision_vantage: unknown provider in handle '$teardown_handle'" >&2; exit 2 ;;
  esac
  register "${t_ip:-0.0.0.0}" decommissioned "torn down ${teardown_handle}"
  echo "torn-down ${teardown_handle}"; exit 0
fi

# ---------------------------------------------------------------------------
# reap: idempotent GC of every gcp VM labelled engagement=<id> (crash self-heal).
# ---------------------------------------------------------------------------
if [[ "$mode" == "reap" ]]; then
  if [[ "$dry_run" -eq 1 ]]; then echo "reaped 0 (dry-run) engagement=${eng_id}"; exit 0; fi
  reaped=0
  while IFS=$'\t' read -r rname rzone; do
    [[ -n "$rname" ]] || continue
    rip="$(gcloud compute instances describe "$rname" --zone "$rzone" --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)"
    gcloud compute instances delete "$rname" --zone "$rzone" --quiet >&2 || true
    provider="gcp"; region="$rzone"
    register "${rip:-0.0.0.0}" decommissioned "reaped ${rname} (engagement=${eng_id})"
    reaped=$((reaped + 1))
  done < <(gcloud compute instances list --filter="labels.engagement=${eng_id}" --format='value(name,zone)' 2>/dev/null || true)
  echo "reaped ${reaped} engagement=${eng_id}"; exit 0
fi

# ---------------------------------------------------------------------------
# create (default mode)
# ---------------------------------------------------------------------------
[[ -n "$provider" ]] || { echo "provision_vantage: --provider is required (gcp|aws|az)" >&2; exit 2; }
[[ -n "$region"   ]] || { echo "provision_vantage: --region is required" >&2; exit 2; }
[[ -n "$name" ]] || name="vantage-${provider}-${region//[^A-Za-z0-9]/-}"

if [[ "$dry_run" -eq 1 ]]; then
  ip="203.0.113.7"                 # TEST-NET-3 (RFC 5737) — deterministic, never a real host
  handle="dry-run:${provider}:${name}"
  register "$ip"
  echo "DRY-RUN provisioned ${provider} vantage: ip=${ip} handle=${handle} region=${region}"
  exit 0
fi

TTL="${PROVISION_TTL_SECONDS:-7200}"   # provider-native max lifetime = SIGKILL-proof crash backstop
case "$provider" in
  gcp)
    zone="$region"
    gcloud compute instances create "$name" \
      --zone "$zone" \
      --machine-type "${PROVISION_GCP_MACHINE:-e2-small}" \
      --image-family "${PROVISION_GCP_IMAGE_FAMILY:-debian-12}" \
      --image-project "${PROVISION_GCP_IMAGE_PROJECT:-debian-cloud}" \
      --labels="engagement=${eng_id},role=attack-vm" \
      --max-run-duration="${TTL}s" --instance-termination-action=DELETE \
      ${PROVISION_SSH_SRC:+--tags="vantage-${eng_id}"} \
      ${extra[@]+"${extra[@]}"} >&2
    # Optional: scope SSH ingress to a single source CIDR (best-effort; additive).
    if [[ -n "${PROVISION_SSH_SRC:-}" ]]; then
      gcloud compute firewall-rules create "allow-ssh-${eng_id}" \
        --allow=tcp:22 --source-ranges="${PROVISION_SSH_SRC}" \
        --target-tags="vantage-${eng_id}" >&2 2>/dev/null || true
    fi
    ip="$(gcloud compute instances describe "$name" --zone "$zone" \
          --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
    handle="gcp:${zone}:${name}"
    ;;
  aws)
    : "${PROVISION_AWS_AMI:?provision_vantage: set PROVISION_AWS_AMI to an image id}"
    iid="$(aws ec2 run-instances --region "$region" \
            --image-id "$PROVISION_AWS_AMI" \
            --instance-type "${PROVISION_AWS_TYPE:-t3.small}" \
            --instance-initiated-shutdown-behavior terminate \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${name}},{Key=engagement,Value=${eng_id}}]" \
            ${extra[@]+"${extra[@]}"} \
            --query 'Instances[0].InstanceId' --output text)"
    aws ec2 wait instance-running --region "$region" --instance-ids "$iid" >&2
    ip="$(aws ec2 describe-instances --region "$region" --instance-ids "$iid" \
          --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
    handle="aws:${region}:${iid}"
    ;;
  az)
    : "${PROVISION_AZ_RG:?provision_vantage: set PROVISION_AZ_RG to a resource group}"
    ip="$(az vm create --resource-group "$PROVISION_AZ_RG" --name "$name" \
           --location "$region" --image "${PROVISION_AZ_IMAGE:-Ubuntu2204}" \
           --public-ip-sku Standard --tags "engagement=${eng_id}" ${extra[@]+"${extra[@]}"} \
           --query publicIpAddress -o tsv)"
    handle="az:${PROVISION_AZ_RG}:${name}"
    ;;
  *)
    echo "provision_vantage: unknown provider '$provider' (gcp|aws|az)" >&2; exit 2;;
esac

[[ -n "${ip:-}" && "$ip" != "None" ]] || { echo "provision_vantage: could not read public IP for ${handle}" >&2; exit 1; }
register "$ip"
if [[ "$ssh_ready" -eq 1 && "$provider" == "gcp" ]]; then
  for _ in $(seq 1 30); do
    gcloud compute ssh "$name" --zone "$region" --command "true" >/dev/null 2>&1 && break || sleep 5
  done
  # Exec channel is up -> prove the egress so the vantage actually counts.
  verify_egress "$ip"
fi
echo "provisioned ${provider} vantage: ip=${ip} handle=${handle} region=${region}"
