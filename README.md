# zeek-ai-detection

Passive AI-service detection with [Zeek](https://zeek.org): find out which devices on a network are talking to which AI services — from mirrored traffic alone. No endpoint agent, no TLS interception, no payload access.

This repo contains the sanitized, open-sourceable parts of the sensor pattern we run in production at [AIQSO](https://aiqso.io): a Zeek detection script, a curated AI-provider domain list, and the capture-path configuration that took us two attempts to get right.

Companion deep-dive: **[Passive AI-service detection with Zeek: architecture and detection limits](https://aiqso.io/blog/passive-ai-service-detection-zeek)** — including the failure stories (a silent `tc` mirror, a bridge that stopped flooding, a sensor OOM) that shaped these configs.

## What's here

| Path | What it is |
|---|---|
| `scripts/ai-services.zeek` | Zeek script — matches DNS queries and TLS SNI against the domain list, writes hits to `ai_services.log` |
| `lists/ai-domains.txt` | Curated AI-provider domains (suffix-matched, so `openai.com` covers `api.openai.com`) |
| `docs/mirror-port-capture.md` | How to build a reliable mirror-port capture path (switch → dedicated NIC → IP-less bridge → sensor), and the silent-failure landmines |
| `examples/node.cfg` | Zeek node config for a dedicated capture interface |
| `examples/interfaces` | Debian/Proxmox `/etc/network/interfaces` stanza for the capture bridge — including the critical `bridge-ageing 0` |

## Quick start

```bash
# Standalone, against a live interface:
zeek -i eth1 scripts/ai-services.zeek \
    AIServices::domains_file=$PWD/lists/ai-domains.txt

# Or against a pcap:
zeek -r capture.pcap scripts/ai-services.zeek \
    AIServices::domains_file=$PWD/lists/ai-domains.txt
```

Each match produces one line in `ai_services.log`:

```
#fields ts	uid	src	domain	query	signal
1752300000.123456	CxT9a41yZbeGuXqLW3	10.20.30.142	openai.com	api.openai.com	sni
1752300012.481202	ClqW2j3rJqYplNbW9h	10.20.30.87	anthropic.com	claude.ai	dns
```

`signal` tells you which passive signal produced the hit: `dns` (a query for an AI-provider name) or `sni` (an encrypted session's TLS Server Name Indication).

Requires Zeek 6.x or later. The domain list is loaded through the input framework with `REREAD` mode, so edits to the list apply without restarting Zeek.

## What this can — and cannot — see

Honesty about detection limits is the point, not a disclaimer:

| Signal | Sees | Cannot see |
|---|---|---|
| DNS queries | Which hosts resolve AI-provider domains, and how often | DNS-over-HTTPS/TLS hides queries (though DoH use is itself a policy signal) |
| TLS SNI | Which AI service an encrypted session is talking to | Encrypted Client Hello (ECH) will erode SNI over time |

Hard blind spots, by design:

- **Local models** (Ollama, llama.cpp) generate no external traffic — invisible to any network-side detection.
- **VPNs, personal hotspots, cellular paths** bypass the monitored network entirely.
- **Content is never visible.** This sees *communication with* AI services, never prompts or responses. Reading content would require a TLS-inspecting proxy or an endpoint agent — which this deliberately is not.
- **Sensor placement bounds everything.** Traffic that never crosses the mirrored link does not exist to the sensor. Get the capture path right first — see `docs/mirror-port-capture.md`.
- **Suffix matching needs a domain to match.** Services fronted by broad cloud domains (e.g. AWS Bedrock under `*.amazonaws.com`) can't be safely suffix-matched and are out of scope for this list.

## The domain list

`lists/ai-domains.txt` is a starting point, not an authority — AI services launch weekly. Entries are suffix-matched on label boundaries. PRs adding or correcting entries are welcome; keep entries specific enough that a match actually means "AI service" (no bare CDN or cloud-provider domains).

## Production use

This pattern (plus device attribution, JA3/JA4 client fingerprinting, flow-shape heuristics, risk scoring, and dashboards) ships as [Faron](https://aiqso.io/faron), our agentless shadow-AI detection product. The Zeek layer here is the foundation; everything above it is the product.

## License

MIT — see [LICENSE](LICENSE).
