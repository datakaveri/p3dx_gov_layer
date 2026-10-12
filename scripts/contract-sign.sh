#!/usr/bin/env bash
# Provider side of contract signing, for driving the gov_layer flow from
# Postman + a terminal (p3dx-auth-ui does the same in the browser with
# WebCrypto). Scheme, as services.ContractSignatureAlgorithm: RSASSA-PKCS1-v1_5
# with SHA-256 over the UTF-8 bytes of the "sha256:<hex>" contract hash.
#
#   keygen       [dir]                                  RSA-2048 key pair -> dir/private.pem, dir/public.pem
#   approve-request <provider_id> <private.pem> <job_id> [gov_url]
#                fetch the JOB_REQUEST for job_id sent to provider_id (data or
#                infra provider), sign its contract hash, print the body for
#                POST /job/approval/{data,infra}-provider
#   sign-request <provider_id> <private.pem> [gov_url] [contract_id]
#                fetch the newest CONTRACT_SIGN request for provider_id, verify
#                the governance signature on its hash, sign the hash
#   sign         <private.pem> <contract_hash>          just the signature (base64)
#   verify       <public.pem> <contract_hash> <signature_b64>
#
# Needs openssl, curl, jq.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

sign_hash() { printf '%s' "$2" | openssl dgst -sha256 -sign "$1" | base64 -w0; }

verify_hash() { # public.pem hash signature_b64
	printf '%s' "$2" | openssl dgst -sha256 -verify "$1" -signature <(printf '%s' "$3" | base64 -d) >/dev/null 2>&1
}

cmd=${1:-}
[ $# -gt 0 ] && shift

case "$cmd" in
keygen)
	dir=${1:-keys/providers/default}
	[ -e "$dir/private.pem" ] && die "$dir/private.pem already exists — reuse it, or pick another dir"
	mkdir -p "$dir"
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/private.pem" 2>/dev/null
	chmod 600 "$dir/private.pem"
	openssl pkey -in "$dir/private.pem" -pubout -out "$dir/public.pem"
	echo "Private key: $dir/private.pem (keep it; never send it anywhere)"
	echo "Public key:  $dir/public.pem"
	echo
	echo "Postman variable data_provider_public_key / infra_provider_public_key (paste exactly this line):"
	jq -Rs . <"$dir/public.pem" | sed 's/^"//; s/"$//'
	;;

approve-request)
	[ $# -ge 3 ] || die "usage: $0 approve-request <provider_id> <private.pem> <job_id> [gov_url]"
	provider_id=$1 key=$2 job_id=$3 gov_url=${4:-http://localhost:8083/api/v1}
	[ -r "$key" ] || die "cannot read private key $key"

	req=$(curl -sf "$gov_url/notifications/$provider_id" | jq --arg job "$job_id" '
		[.notifications[] | select(.payload.type == "JOB_REQUEST" and .payload.job_id == $job)] | first') ||
		die "could not fetch notifications from $gov_url"
	[ "$req" != "null" ] || die "no JOB_REQUEST for job $job_id sent to $provider_id"

	hash=$(jq -r .payload.contract_hash <<<"$req")
	[ -n "$hash" ] && [ "$hash" != "null" ] || die "the job request carries no contract_hash"
	signature=$(sign_hash "$key" "$hash")
	echo "$(jq -r .message <<<"$req")"
	echo "role:          $(jq -r .payload.role <<<"$req")"
	echo "contract_id:   $(jq -r .payload.contract_id <<<"$req")"
	echo "contract_hash: $hash"
	echo
	echo "Postman variable data_provider_signature / infra_provider_signature:"
	echo "$signature"
	echo
	echo "Body for $(jq -r .payload.approve_with <<<"$req"):"
	jq -n --arg j "$job_id" --arg h "$hash" --arg s "$signature" '{job_id: $j, contract_hash: $h, signature: $s}'
	;;

sign-request)
	[ $# -ge 2 ] || die "usage: $0 sign-request <provider_id> <private.pem> [gov_url] [contract_id]"
	provider_id=$1 key=$2 gov_url=${3:-http://localhost:8083/api/v1} contract_id=${4:-}
	[ -r "$key" ] || die "cannot read private key $key"

	req=$(curl -sf "$gov_url/notifications/$provider_id" | jq --arg cid "$contract_id" '
		[.notifications[] | select(.payload.type == "CONTRACT_SIGN")
		 | select($cid == "" or .payload.contract_id == $cid)] | first') ||
		die "could not fetch notifications from $gov_url"
	[ "$req" != "null" ] || die "no CONTRACT_SIGN request for $provider_id${contract_id:+ and contract $contract_id} — is the job approved yet?"

	notification_id=$(jq -r .id <<<"$req")
	contract_id=$(jq -r .payload.contract_id <<<"$req")
	hash=$(jq -r .payload.contract_hash <<<"$req")
	gov_sig=$(jq -r .payload.governance_signature <<<"$req")
	gov_pub=$(mktemp)
	trap 'rm -f "$gov_pub"' EXIT
	jq -r .payload.governance_public_key <<<"$req" >"$gov_pub"

	# The provider only signs a hash the governance layer itself signed.
	verify_hash "$gov_pub" "$hash" "$gov_sig" || die "governance signature on $hash does NOT verify — do not sign"

	signature=$(sign_hash "$key" "$hash")
	echo "contract_id:          $contract_id"
	echo "contract_hash:        $hash"
	echo "governance signature: verified"
	echo
	echo "Postman variable signature:"
	echo "$signature"
	echo
	echo "Body for POST /contracts/$contract_id/sign:"
	jq -n --arg n "$notification_id" --arg h "$hash" --arg s "$signature" \
		'{notification_id: $n, contract_hash: $h, signature: $s}'
	;;

sign)
	[ $# -eq 2 ] || die "usage: $0 sign <private.pem> <contract_hash>"
	sign_hash "$1" "$2"
	echo
	;;

verify)
	[ $# -eq 3 ] || die "usage: $0 verify <public.pem> <contract_hash> <signature_b64>"
	if verify_hash "$1" "$2" "$3"; then echo "signature OK"; else die "signature does NOT verify"; fi
	;;

*)
	sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
	[ -n "$cmd" ] && exit 1
	;;
esac
