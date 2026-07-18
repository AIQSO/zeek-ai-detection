# Encrypted DNS: detecting it, and keeping your DNS visibility

The DNS signal in `ai-services.zeek` assumes devices use the network's
resolver over plaintext port 53. Encrypted DNS breaks that assumption:

- **DoH** (DNS over HTTPS, port 443) — indistinguishable from web
  traffic except by *where it goes*
- **DoT** (DNS over TLS, TCP port 853)
- **DoQ** (DNS over QUIC, UDP port 853, RFC 9250)

A host using any of these still shows up in TLS-SNI hits, but its DNS
queries go dark. `scripts/dns-evasion.zeek` tells you **which hosts**
that is happening on, and this doc covers the two network-side controls
that keep most managed traffic on the resolver you can see: the DoH
canary and resolver blocking.

Read the hits the right way: encrypted DNS is a privacy feature that
browsers enable by default, not evidence of wrongdoing. A `doh-sni` hit
means "my DNS visibility is degraded for this device" — and on a network
that has deployed the canary and resolver blocking, it means a device is
actively configured around policy, which is itself worth knowing.

## Detection

```bash
zeek -i eth1 scripts/dns-evasion.zeek \
    DNSEvasion::resolvers_file=$PWD/lists/doh-resolvers.txt
```

One line per hit in `dns_evasion.log`; the `signal` column:

| Signal | Meaning |
|---|---|
| `doh-dns` | Host looked up a known public DoH/DoT resolver name — usually the bootstrap step right before DoH turns on |
| `doh-sni` | TLS session to a known resolver — DoH is in use *now* |
| `dot` | TCP connection to port 853 |
| `doq` | UDP flow to port 853 |
| `canary` | Query for `use-application-dns.net` — a Firefox-family browser is deciding whether to enable DoH |

`lists/doh-resolvers.txt` has the same format and suffix-match semantics
as the AI-domain list, and the same caveat: it's a starting point.
Entries must be resolver *service* endpoints, not DNS companies'
marketing sites — visiting `quad9.net` to read about Quad9 is not DNS
evasion, which is why the list carries `dns.quad9.net` and friends
rather than the bare domain.

## The DoH canary

Firefox resolves `use-application-dns.net` through the system resolver
before enabling DoH. If the answer is NXDOMAIN (or has no A/AAAA
records), Firefox concludes the network operator has an intentional DNS
setup and leaves DoH off. Returning NXDOMAIN for that name is the
cheapest DoH control that exists — one resolver config line:

**unbound**

```
local-zone: "use-application-dns.net." always_nxdomain
```

**dnsmasq**

```
server=/use-application-dns.net/
```

**Pi-hole** — FTL answers NXDOMAIN for the canary by default; nothing to
configure.

**BIND**

```
zone "use-application-dns.net" { type primary; file "/etc/bind/db.empty"; };
```

**Windows DNS** — create an empty primary zone named
`use-application-dns.net`.

Verify from a client: `nslookup use-application-dns.net` must return
NXDOMAIN, and the sensor should log a `canary` hit for the query.

## Blocking resolvers

The canary is advisory and only Firefox honors it. The enforcement layer
is egress filtering:

- **Block outbound TCP/853 and UDP/853** except from your own resolver.
  Nothing legitimate on a client network needs DoT/DoQ directly.
- **Block the known DoH resolver endpoints on 443** —
  `lists/doh-resolvers.txt` is usable as the seed for a firewall or
  DNS-RPZ deny list. Because DoH resolvers must be reachable by IP
  bootstrap too, also block the well-known anycast addresses (8.8.8.8,
  8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9) on 443 from clients.
- Let your own resolver do DoH/DoT **upstream** if you want transport
  privacy — encrypt the path to the internet, keep the visible path
  inside the network.

What each client does when blocked:

| Client | Behavior |
|---|---|
| Firefox | Canary NXDOMAIN → DoH stays off. Exception: a user who *explicitly* enabled "Max Protection" mode ignores the canary; blocking the resolver then hard-fails their DNS until they revert |
| Chrome / Edge | No canary. Auto-upgrades to DoH only when the *system* resolver is a known DoH provider — a network running its own resolver never triggers it. If the DoH endpoint is blocked, falls back to plaintext |
| iOS / Android encrypted-DNS profiles | Use port 853 or listed DoH endpoints — caught by the blocks above; OS falls back or fails visibly |
| Apps with hardcoded DoH | Ignore the canary entirely. Blocking the resolver forces a fallback or a visible failure; the `doh-sni` / `dot` hits tell you which hosts these are |

## The ECH horizon, and what's deliberately not here

Encrypted Client Hello (RFC 9849) encrypts the SNI itself as adoption
spreads, which erodes this repo's second signal the way DoH erodes the
first. The mitigation ladder, in order of increasing effort:

1. **Destination IP/ASN attribution** — AI providers' egress ranges are
   fewer and slower-moving than their hostnames.
2. **TLS client fingerprinting (JA4)** — fingerprints the *client hello
   shape*, which ECH does not hide. A Zeek package exists
   ([FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)). Two things to
   know before building on it: fingerprints are "consistent with client
   X", never identification; and while the JA4 fingerprint itself is
   BSD-3-licensed, the wider JA4+ suite is under the FoxIO License 1.1 —
   review its terms before embedding JA4+ in a commercial product.
3. **Endpoint telemetry** — outside this repo's passive, network-only
   scope by design.

None of these ship here: this repo stays the sanitized DNS + SNI
foundation. See the README's production-use note for where the rest
lives.
