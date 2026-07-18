# Contributing

Most contributions to this repo are domain-list changes, so most of this
file is about the acceptance bar for `lists/ai-domains.txt`. Fixes to the
Zeek script and docs are welcome too — same PR flow.

## Domain list: what gets accepted

The test for every entry: **does a match unambiguously mean "this device
talked to an AI service"?** If a match could just as easily be ordinary
non-AI traffic, the entry does more harm than good.

Accepted:

- AI chat/assistant products (`claude.ai`, `kimi.com`)
- AI model/inference APIs (`groq.com`, `deepgram.com`)
- AI coding tools (`cursor.com`, `windsurf.com`)
- AI media generation (`midjourney.com`, `elevenlabs.io`)
- Provider-specific subdomains of broad platforms
  (`openai.azure.com`, `dashscope.aliyuncs.com`)

Rejected:

- Bare CDN or cloud-provider domains (`amazonaws.com`, `cloudfront.net`) —
  services fronted only by these (e.g. AWS Bedrock) are out of scope, as
  the README explains
- General-purpose products that merely *have* an AI feature
  (`notion.so`, `zoom.us`) — a match doesn't mean AI use
- Subdomains of an existing entry (`api.openai.com` when `openai.com` is
  listed) — entries are suffix-matched, so the longer one is redundant

## Domain list: format

The file is read by Zeek's input framework, so the format is strict:

- First line must be exactly `#fields<TAB>domain`
- One domain per line: lowercase, no comments, no blank lines
- Every entry needs at least two labels (no bare TLDs)

Check before you push — CI runs the same script:

```bash
python3 scripts/check-domains.py lists/ai-domains.txt
```

In the PR description, say what the service is and link its site, so
review doesn't require guessing.

## Zeek script changes

CI parse-checks `scripts/ai-services.zeek` with `zeek --parse-only`
(Zeek 6.x). For behavior changes, please include the output of a run
against a pcap that exercises the change.

Keep the design constraint in mind: this script is deliberately passive.
Changes that touch payloads, decrypt anything, or identify people rather
than devices are out of scope for this repo.

## License

Contributions are accepted under Apache-2.0 (see `LICENSE`). By
submitting a PR you agree your contribution is licensed under the same
terms.
