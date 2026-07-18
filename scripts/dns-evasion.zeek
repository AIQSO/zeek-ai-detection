##! Passive DNS-evasion visibility for Zeek.
##!
##! The companion to ai-services.zeek: that script tells you which hosts
##! talk to AI services; this one tells you which hosts are taking their
##! DNS somewhere the sensor cannot see it. Encrypted DNS is the main way
##! the DNS signal in ai-services.zeek goes dark, so treat these hits as
##! "my visibility is degraded for this host" — not as wrongdoing.
##!
##! Signals, one line in dns_evasion.log per hit:
##!
##!   doh-dns  — DNS query for a known public DoH/DoT resolver name
##!   doh-sni  — TLS session whose SNI is a known resolver (DoH in use)
##!   dot      — TCP connection to port 853 (DNS over TLS)
##!   doq      — UDP flow to port 853 (DNS over QUIC, RFC 9250)
##!   canary   — query for use-application-dns.net: a Firefox-family
##!              browser is deciding whether to enable DoH
##!
##! Deploying the canary answer and blocking resolvers are resolver and
##! firewall configuration, not Zeek's job — see docs/dns-evasion.md.
##!
##! Usage:
##!   zeek -i eth1 dns-evasion.zeek DNSEvasion::resolvers_file=/path/to/doh-resolvers.txt
##!
##! Requires Zeek 6.x or later.

@load base/frameworks/input
@load base/protocols/dns
@load base/protocols/ssl

module DNSEvasion;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:        time   &log;
		uid:       string &log &optional;
		src:       addr   &log;
		## What matched: the resolver-list entry, the canary domain,
		## or "tcp/853" / "udp/853" for port-based hits.
		indicator: string &log;
		## The full observed name (DNS query or TLS SNI), or the
		## destination address for port-based hits.
		query:     string &log;
		## Which signal produced the hit — see the header comment.
		signal:    string &log;
	};

	## Path to the resolver list. Same format as lists/ai-domains.txt:
	## a "#fields\tdomain" header, then one domain per line,
	## suffix-matched on label boundaries.
	const resolvers_file = "doh-resolvers.txt" &redef;

	## Firefox resolves this name before enabling DoH; an NXDOMAIN
	## answer tells it to stay on the system resolver. Seeing the query
	## is informational — it means a browser is making that decision.
	const canary_domain = "use-application-dns.net" &redef;
}

type Idx: record {
	domain: string;
};

global doh_resolvers: set[string] = set();

event zeek_init()
	{
	Log::create_stream(DNSEvasion::LOG, [$columns=Info, $path="dns_evasion"]);
	Input::add_table([$source=resolvers_file, $name="doh_resolvers",
	                  $idx=Idx, $destination=doh_resolvers,
	                  $mode=Input::REREAD]);

	# Same async-load race as ai-services.zeek: hold packet processing
	# until the list is in, or a pcap run can match against an empty
	# table. Caveat: continue_processing() is not reference-counted, so
	# if this script and ai-services.zeek run together, whichever list
	# loads first resumes processing for both. The window is the load
	# time of two small files — negligible on live traffic, and both
	# lists are loaded before packet 1 in every pcap run we've seen.
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "doh_resolvers" )
		continue_processing();
	}

## Suffix-match a name against the resolver set on label boundaries.
## Returns the matching list entry, or "" if none.
function match_resolver(name: string): string
	{
	local candidate = to_lower(sub(name, /\.+$/, ""));

	while ( |candidate| > 0 )
		{
		if ( candidate in doh_resolvers )
			return candidate;

		local dot = strstr(candidate, ".");
		if ( dot == 0 )
			break;

		candidate = sub_bytes(candidate, dot + 1, |candidate| - dot);
		}

	return "";
	}

## True when the name is the canary domain or a label under it.
function is_canary(name: string): bool
	{
	local n = to_lower(sub(name, /\.+$/, ""));
	return n == canary_domain || ends_with(n, "." + canary_domain);
	}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( ! rec?$query )
		return;

	if ( is_canary(rec$query) )
		{
		Log::write(DNSEvasion::LOG, [$ts=rec$ts, $uid=rec$uid,
		                             $src=rec$id$orig_h, $indicator=canary_domain,
		                             $query=rec$query, $signal="canary"]);
		return;
		}

	local m = match_resolver(rec$query);
	if ( m == "" )
		return;

	Log::write(DNSEvasion::LOG, [$ts=rec$ts, $uid=rec$uid,
	                             $src=rec$id$orig_h, $indicator=m,
	                             $query=rec$query, $signal="doh-dns"]);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	if ( ! rec?$server_name )
		return;

	local m = match_resolver(rec$server_name);
	if ( m == "" )
		return;

	Log::write(DNSEvasion::LOG, [$ts=rec$ts, $uid=rec$uid,
	                             $src=rec$id$orig_h, $indicator=m,
	                             $query=rec$server_name, $signal="doh-sni"]);
	}

event connection_established(c: connection)
	{
	if ( c$id$resp_p != 853/tcp )
		return;

	Log::write(DNSEvasion::LOG, [$ts=c$start_time, $uid=c$uid,
	                             $src=c$id$orig_h, $indicator="tcp/853",
	                             $query=fmt("%s", c$id$resp_h), $signal="dot"]);
	}

event new_connection(c: connection)
	{
	# TCP is handled by connection_established (a completed handshake
	# beats a lone SYN); only UDP port 853 — DNS over QUIC — lands here.
	if ( c$id$resp_p != 853/udp )
		return;

	Log::write(DNSEvasion::LOG, [$ts=c$start_time, $uid=c$uid,
	                             $src=c$id$orig_h, $indicator="udp/853",
	                             $query=fmt("%s", c$id$resp_h), $signal="doq"]);
	}
