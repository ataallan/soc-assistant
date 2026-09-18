# Wazuh setup (Manager API + Indexer)

This SOC assistant **prefers the Wazuh Indexer** (`wazuh-alerts-*`) for security alerts.
The Manager API endpoint `/manager/logs` is **never** used as an alert source — those are
manager module logs (for example `wazuh-modulesd:syscollector` "Evaluation finished") and
usually have **no** `data.srcip`, which made triage IP show as "not in alert".

## Environment (Windows host)

Copy `.env.example` → `.env` (never commit `.env`).

```env
# Manager API (reachable from Windows on :55000 in typical all-in-one labs)
WAZUH_API=https://localhost:55000
WAZUH_USER=wazuh
WAZUH_PASS=your-manager-api-password

# Indexer (OpenSearch) — real alerts
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-admin-password
WAZUH_INDEXER_INDEX=wazuh-alerts*
# Indexer often binds 127.0.0.1 *inside WSL only* — not on the Windows host.
# When the dashboard runs on Windows, set:
WAZUH_INDEXER_VIA_WSL=true
```

With `WAZUH_INDEXER_VIA_WSL=true`, the client runs `wsl -e curl ...` against the indexer
URL so traffic hits WSL localhost. Leave `false` when Python itself runs inside WSL or
can reach the indexer directly.

## Health page

`/health` shows Manager API auth plus **Alert source** / **Indexer** status:
preferred path (`indexer` vs `manager_api`), last successful source, and a reminder that
`/manager/logs` is not used for alerts.

## Generating alerts that include attacker IPs (`srcip`)

Many default lab alerts are **dpkg install**, **FIM checksum changed**, or **PAM session**
events — they correctly have **no attacker IP**. Host / package / hash / CVE observables
populate first.

To see `data.srcip` in triage:

1. **sshd auth** — enable auth log collection on an agent; generate failed/invalid logins
   (Wazuh rules in the 57xx band often carry `srcip`).
2. **Firewall / IDS** — forward firewall deny or Suricata/Zeek events that include client IP.
3. Avoid relying on Manager module logs; always query **Indexer** `wazuh-alerts-*`.

## Useful Wazuh capabilities (high level)

| Capability | What you get | Typical observables |
| --- | --- | --- |
| Vulnerability detection | Package CVE findings | `cve`, host, package |
| Syscheck (FIM) | Integrity checksum changes | host, file hash, path |
| Rootcheck | Rootkit/policy checks | host (rule id bands ~510–539) |
| DNS / web proxy logs | Query and destination names | domain, host (sometimes IP) |
| Auth logs (sshd, Windows) | Failures / invalid users | **srcip**, user, host |

## Observables in this app

Normalize extracts **host** (agent name), **file_hash** (syscheck md5/sha256), **domain**
(DNS query fields), and **cve** (vulnerability detector). They soft-migrate onto triage
rows and cases. UI shows **not in alert** when a field is absent.

## Safety

Never commit real passwords, `.env`, or database files.
