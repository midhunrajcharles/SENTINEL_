# SENTINEL CIM Mapping Guide

How SENTINEL maps to Splunk's Common Information Model (CIM) data models, which
sourcetypes and fields are required, how to onboard data, and how to write field
extractions for custom sources.

---

## Why CIM Matters for SENTINEL

SENTINEL's SPL templates and SAIA-generated queries reference CIM-normalised field
names (`process_name`, `user`, `dest_ip`, `bytes_out`) rather than raw sourcetype
fields (`Process.Image`, `duser`, `netflow.dst_addr`). This means:

- A query written for CrowdStrike EDR data works unchanged with SentinelOne, Carbon
  Black, or Sysmon — as long as each is CIM-mapped.
- MCP tools like `get_process_tree` and `get_network_flows` do not need to know which
  EDR vendor is deployed.
- New data sources can be onboarded without changing agent code — only a CIM add-on
  is needed.

---

## CIM Data Models Used by SENTINEL

| CIM Data Model | Used By | Key Fields |
|---------------|---------|-----------|
| Endpoint.Processes | Vanguard, Sherlock Phase A/B | `process_name`, `parent_process_name`, `command_line`, `user`, `host`, `pid`, `parent_process_id` |
| Endpoint.Filesystem | Sherlock Phase B, Executor (quarantine) | `file_path`, `file_name`, `action`, `file_hash`, `process_name` |
| Endpoint.Registry | Sherlock Phase B | `registry_path`, `registry_value_name`, `registry_value_data`, `action` |
| Network.Traffic | Sherlock Phase C | `src_ip`, `dest_ip`, `dest_port`, `bytes_out`, `bytes_in`, `protocol`, `action` |
| Network.DNS | Sherlock Phase C | `query`, `record_type`, `reply_code`, `src_ip`, `message_type` |
| Authentication | Sherlock Phase D | `user`, `src_ip`, `dest`, `action`, `result`, `logon_type`, `signature` |
| Identity.Management | Sherlock Phase D | `user`, `action`, `object_category`, `object`, `result` |
| Alerts | Vanguard | `alert_type`, `severity`, `host`, `user`, `risk_score` |

---

## Required Sourcetypes and Field Mappings

### Endpoint Data (EDR / Sysmon)

SENTINEL expects endpoint data in the `endpoint` or `edr` index. The `Endpoint`
CIM data model must be configured in each sourcetype's add-on (`TA-*`).

#### Sysmon (Windows Event Log)

| Raw Field | CIM Field | Notes |
|-----------|-----------|-------|
| `Image` | `process_path` | Full path including filename |
| `OriginalFileName` or `Image` (basename) | `process_name` | Filename only |
| `ParentImage` | `parent_process_path` | |
| `CommandLine` | `command_line` | |
| `User` | `user` | Format: `DOMAIN\username` |
| `ProcessId` | `pid` | Integer |
| `ParentProcessId` | `parent_process_id` | Integer |
| `UtcTime` | `_time` | Already converted by Sysmon TA |
| `Computer` | `host` | |
| `Hashes` (SHA256 portion) | `process_hash_sha256` | Extracted by TA |
| `TargetFilename` | `file_path` | For Event ID 11 (FileCreate) |
| `TargetObject` | `registry_path` | For Event IDs 12/13/14 |

Recommended TA: **Splunk Add-on for Microsoft Windows** (available on Splunkbase).

#### CrowdStrike EDR

| Raw Field | CIM Field |
|-----------|-----------|
| `FileName` | `process_name` |
| `FilePath` | `process_path` |
| `CommandLine` | `command_line` |
| `UserName` | `user` |
| `ContextProcessId` | `pid` |
| `ParentProcessId` | `parent_process_id` |
| `ParentImageFileName` | `parent_process_name` |
| `LocalAddressIP4` | `src_ip` |
| `RemoteAddressIP4` | `dest_ip` |
| `RemotePort` | `dest_port` |
| `SHA256HashData` | `process_hash_sha256` |

Recommended TA: **Falcon Data Replicator Add-on for Splunk**.

#### SentinelOne

| Raw Field | CIM Field |
|-----------|-----------|
| `process.name` | `process_name` |
| `process.imagePath` | `process_path` |
| `process.cmdLine` | `command_line` |
| `process.user.name` | `user` |
| `process.pid` | `pid` |
| `process.parentPid` | `parent_process_id` |
| `src.ip.address` | `src_ip` |
| `networkSrc.port` | `src_port` |

Recommended TA: **SentinelOne Add-on for Splunk**.

### Network Data

Network data should land in the `network` index, normalised to the `Network_Traffic`
CIM data model.

#### Zeek (Bro)

| Sourcetype | Raw Field | CIM Field |
|-----------|-----------|-----------|
| `bro:conn:json` | `id.orig_h` | `src_ip` |
| `bro:conn:json` | `id.resp_h` | `dest_ip` |
| `bro:conn:json` | `id.resp_p` | `dest_port` |
| `bro:conn:json` | `orig_bytes` | `bytes_out` |
| `bro:conn:json` | `resp_bytes` | `bytes_in` |
| `bro:conn:json` | `proto` | `protocol` |
| `bro:conn:json` | `conn_state` | `action` (mapped: S1→allowed, REJ→blocked) |
| `bro:dns:json` | `query` | `query` |
| `bro:dns:json` | `qtype_name` | `record_type` |

Recommended TA: **Splunk Add-on for Zeek (Bro)**.

#### Palo Alto Networks (Firewall)

| Raw Field | CIM Field |
|-----------|-----------|
| `src` | `src_ip` |
| `dst` | `dest_ip` |
| `dport` | `dest_port` |
| `bytes_sent` | `bytes_out` |
| `bytes_received` | `bytes_in` |
| `proto` | `protocol` |
| `action` | `action` |
| `app` | `app` |
| `category` | `url_category` |

Recommended TA: **Splunk Add-on for Palo Alto Networks**.

### Identity Data

Identity data should land in the `identity` index, normalised to the `Authentication`
and `Identity_Management` CIM data models.

#### Windows Security Event Log (Logon events)

| Event ID | CIM Field | Raw Field |
|----------|-----------|-----------|
| 4624/4625 | `user` | `TargetUserName` |
| 4624/4625 | `src_ip` | `IpAddress` |
| 4624/4625 | `dest` | `ComputerName` |
| 4624/4625 | `action` | `success` (4624) / `failure` (4625) |
| 4624/4625 | `logon_type` | `LogonType` |
| 4648 | `user` | `SubjectUserName` |
| 4648 | `dest` | `TargetServerName` |
| 4720/4726 | `action` | `created` / `deleted` |
| 4720/4726 | `object` | `TargetUserName` |

#### Azure Active Directory / Entra ID

| Raw Field | CIM Field |
|-----------|-----------|
| `userPrincipalName` | `user` |
| `ipAddress` | `src_ip` |
| `clientAppUsed` | `app` |
| `status.errorCode` == 0 | `action = success` |
| `status.errorCode` != 0 | `action = failure` |
| `riskLevelDuringSignIn` | `risk_level` |

Recommended TA: **Splunk Add-on for Microsoft Cloud Services**.

---

## Data Onboarding Requirements

### Minimum Viable Data Set

SENTINEL can operate in reduced-capability mode with only these sources:

| Source | Index | Required For |
|--------|-------|-------------|
| Splunk ES notable alerts | `notable` | Vanguard (alert intake) |
| Windows Event Log (Security) | `wineventlog` | Sherlock Phase D (identity) |
| Any EDR with Endpoint CIM | `endpoint` or `edr` | Sherlock Phase A/B (process tree) |

Without network data, Phase C (lateral movement) uses only ES notable data.
Without EDR data, Phases A and B fall back to Windows Event Log process creation events.

### Full Coverage Data Set

| Source | Index | Enables |
|--------|-------|---------|
| EDR (CrowdStrike/S1/Sysmon) | `endpoint` or `edr` | Full process trees, file activity, registry |
| Firewall/Zeek | `network` | Lateral movement, C2 beaconing, data exfiltration |
| DNS logs | `network` or `dns` | DNS tunnelling, domain IOC matching |
| IAM/Auth (AD/Entra/Okta) | `identity` | Identity investigation, impossible travel |
| Threat intelligence | `threat_intel` | IOC enrichment in Phase E |
| Proxy/web gateway | `proxy` or `web` | URL analysis, HTTPS inspection |

### Index Configuration

Create the required indexes before installing SENTINEL:

```bash
# Create all SENTINEL-specific indexes
for INDEX in endpoint edr network identity proxy dns threat_intel sentinel_audit sentinel_learning; do
    $SPLUNK_HOME/bin/splunk add index $INDEX \
        -maxDataSize 50000 \
        -frozenTimePeriodInSecs 7776000 \
        -auth admin:changeme
done
```

Recommended index sizes for a 1000-endpoint environment:

| Index | Daily Ingest | 90-day Retention | Disk |
|-------|-------------|-----------------|------|
| `endpoint` | 20–50 GB | 90 days | 2–4 TB |
| `network` | 50–200 GB | 30 days | 2–6 TB |
| `identity` | 1–5 GB | 90 days | 100–500 GB |
| `sentinel_audit` | < 1 GB | 365 days | 100–365 GB |
| `sentinel_learning` | < 100 MB | 365 days | 40 GB |

---

## Field Extraction Specifications

For custom data sources not covered by an existing TA, write field extractions in
`$SPLUNK_HOME/etc/apps/sentinel/default/transforms.conf`.

### Example: Custom EDR JSON Extraction

```ini
# transforms.conf — custom EDR sourcetype CIM mapping
[custom_edr_process_extraction]
SOURCE_KEY    = _raw
REGEX         = \{.*\}
FORMAT        = $0
MV_ADD        = false

[custom_edr_kv_extraction]
SOURCE_KEY    = _raw
SHOULD_LINEMERGE = false
KV_MODE       = json
```

```ini
# props.conf — apply extractions and CIM field aliases
[custom_edr_events]
SHOULD_LINEMERGE    = false
KV_MODE             = json
TIME_PREFIX         = "timestamp":
TIME_FORMAT         = %s

# CIM aliases: map raw field names to CIM field names
FIELDALIAS-process_name     = ProcessName   AS process_name
FIELDALIAS-parent_process   = ParentProcess AS parent_process_name
FIELDALIAS-command_line     = CmdLine       AS command_line
FIELDALIAS-user             = AccountName   AS user
FIELDALIAS-pid              = PID           AS pid
FIELDALIAS-parent_pid       = PPID          AS parent_process_id
FIELDALIAS-host             = ComputerName  AS host
FIELDALIAS-sha256           = HashSHA256    AS process_hash_sha256

# Tag this sourcetype so CIM data model acceleration includes it
TAGS                         = endpoint process
```

### Validating CIM Mapping

After adding a new sourcetype, verify CIM compliance:

```spl
| datamodel Endpoint Processes search
| search host="DESKTOP-ABC123"
| table process_name, parent_process_name, command_line, user, pid, host
| head 10
```

All five CIM fields should be populated. If a field is null, the CIM mapping is
incomplete — check `FIELDALIAS` entries in `props.conf`.

Use the **Splunk Common Information Model (CIM) Validator** app from Splunkbase to
run automated CIM compliance checks across all sourcetypes.

---

## Asset Criticality Lookup

SENTINEL's `get_asset_context` tool reads from the `asset_criticality_lookup` KV Store
collection. Populate it before running SENTINEL:

```spl
| inputlookup asset_criticality_lookup
| append [
    | makeresults count=1
    | eval
        asset_name       = "DESKTOP-ABC123",
        asset_type       = "workstation",
        criticality_score = 1.2,
        criticality_label = "HIGH",
        environment       = "corporate",
        owner             = "jdoe",
        os                = "Windows 10 22H2",
        last_seen         = now()
  ]
| outputlookup asset_criticality_lookup
```

For bulk import from a CMDB CSV:

```bash
$SPLUNK_HOME/bin/splunk add oneshot /path/to/cmdb_export.csv \
    -index _internal \
    -sourcetype asset_import \
    -auth admin:changeme
```

Then run the `SENTINEL - Import CMDB Assets` saved search to transform and load
the data into `asset_criticality_lookup`.

**Criticality label to score mapping:**

| Label | Score | Multiplier Effect |
|-------|-------|------------------|
| CRITICAL | 1.5+ | Risk score ×1.5 |
| HIGH | 1.2 | Risk score ×1.2 |
| MEDIUM | 1.0 | Risk score ×1.0 (no change) |
| LOW | 0.5 | Risk score ×0.5 |
| UNKNOWN | 1.0 | Default (no CMDB entry) |
