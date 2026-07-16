---
runbook: true
repo: zeek-ai-detection
status: shipped
type: tool
updated: 2026-07-16
health: unknown
deploy: not deployed
next: maintain domain list and review capture-path reliability
---

# zeek-ai-detection — Runbook

## Purpose

Passive AI-service detection with Zeek. The repository detects devices talking to AI services from mirrored network traffic using DNS queries and TLS SNI, without endpoint agents, TLS interception, or payload access.

The open-source parts are a Zeek script, an AI-provider domain list, and capture-path configuration for a mirror-port sensor. README says the broader pattern ships as Faron, AIQSO's agentless shadow-AI detection product.

## Stack

- Zeek 6.x or later.
- `scripts/ai-services.zeek` writes matches to `ai_services.log`.
- `lists/ai-domains.txt` is suffix-matched on label boundaries and loaded with `REREAD` mode.
- Signals: DNS query names and TLS SNI.
- Example Zeek node config: `examples/node.cfg`.
- Example Debian/Proxmox capture bridge config: `examples/interfaces`.

## Where it runs

The documented capture path is:

```text
LAN devices -> aggregation switch mirror port -> dedicated hypervisor capture NIC -> IP-less bridge -> sensor container eth1 -> Zeek -> ai_services.log
```

The sensor interface in `examples/node.cfg` is `eth1`. The capture bridge shown in docs is `vmbr2` with `bridge-ageing 0`. Hosts, URLs, production deployment targets, and live service status are unknown from this repository.

## Run / deploy

Run against a live interface:

```bash
zeek -i eth1 scripts/ai-services.zeek \
    AIServices::domains_file=$PWD/lists/ai-domains.txt
```

Run against a pcap:

```bash
zeek -r capture.pcap scripts/ai-services.zeek \
    AIServices::domains_file=$PWD/lists/ai-domains.txt
```

Configure standalone Zeek with the example sensor interface:

```bash
cat examples/node.cfg
```

No deploy command is documented in the repository.

## Health & recovery

Health status is unknown from the repository.

Capture-path checks from the docs:

```bash
tcpdump -i eth1 -c 20
```

Expected signs of health:

- `tcpdump` on the sensor sees traffic between other hosts, not only the sensor host.
- `ssl.log` contains `server_name` values.
- Opening a known AI service from a workstation creates an `ai_services.log` hit with that workstation's IP.

Recovery notes from the docs:

- Use a real switch mirror port instead of a host-side `tc` mirror.
- Mirror inside the NAT boundary so device attribution is preserved.
- Keep the capture NIC out of any LACP bond.
- Use `bridge-ageing 0` on the IP-less capture bridge.
- Put the sensor interface in promiscuous mode.
- Size Zeek for mirror load; docs mention a 1 GB container limit caused OOM and 4 GB is now used.
- Monitor the Zeek process, not only any log forwarder or pipeline heartbeat.

## Current status

The last 30 commit messages show an initial release for passive AI-service detection with Zeek, followed by relicensing from MIT to Apache-2.0 with patent grant and explicit trademark non-grant. README presents this repository as the sanitized, open-sourceable Zeek foundation for a pattern used in production at AIQSO and says the broader product ships as Faron.

## Links

- README: `README.md`
- Capture guide: `docs/mirror-port-capture.md`
- Zeek script: `scripts/ai-services.zeek`
- Domain list: `lists/ai-domains.txt`
- Example node config: `examples/node.cfg`
- Example bridge config: `examples/interfaces`
- License: `LICENSE`
