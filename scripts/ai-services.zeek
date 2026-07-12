##! Passive AI-service detection for Zeek.
##!
##! Watches DNS queries and TLS SNI values for matches against a curated
##! list of AI-provider domains (suffix-matched), and writes each hit to
##! its own log stream: ai_services.log.
##!
##! This is deliberately passive: it never touches payloads, never
##! decrypts anything, and identifies devices/services — not people or
##! prompt content. See README.md for what this approach can and cannot
##! see.
##!
##! Usage:
##!   zeek -i eth1 ai-services.zeek AIServices::domains_file=/path/to/ai-domains.txt
##!
##! Requires Zeek 6.x or later.

@load base/frameworks/input
@load base/protocols/dns
@load base/protocols/ssl

module AIServices;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:     time   &log;
		uid:    string &log &optional;
		src:    addr   &log;
		## The list entry that matched (e.g. "openai.com").
		domain: string &log;
		## The full observed name (DNS query or TLS SNI).
		query:  string &log;
		## Which signal produced the hit: "dns" or "sni".
		signal: string &log;
	};

	## Path to the domain list. One domain per line in Zeek input-framework
	## format (the file must start with a "#fields\tdomain" header — see
	## lists/ai-domains.txt). Entries are suffix-matched on label
	## boundaries, so "openai.com" also matches "api.openai.com".
	const domains_file = "ai-domains.txt" &redef;
}

type Idx: record {
	domain: string;
};

global ai_domains: set[string] = set();

event zeek_init()
	{
	Log::create_stream(AIServices::LOG, [$columns=Info, $path="ai_services"]);
	Input::add_table([$source=domains_file, $name="ai_domains",
	                  $idx=Idx, $destination=ai_domains,
	                  $mode=Input::REREAD]);

	# The input framework loads the domain list asynchronously. Without
	# this, a pcap run (zeek -r) races the load and can process every
	# packet against an EMPTY table — zero matches, no error. Hold packet
	# processing until the list is in.
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "ai_domains" )
		continue_processing();
	}

## Suffix-match a name against the domain set on label boundaries.
## Returns the matching list entry, or "" if none.
function match_domain(name: string): string
	{
	local candidate = to_lower(sub(name, /\.+$/, ""));

	while ( |candidate| > 0 )
		{
		if ( candidate in ai_domains )
			return candidate;

		local dot = strstr(candidate, ".");
		if ( dot == 0 )
			break;

		candidate = sub_bytes(candidate, dot + 1, |candidate| - dot);
		}

	return "";
	}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( ! rec?$query )
		return;

	local m = match_domain(rec$query);
	if ( m == "" )
		return;

	Log::write(AIServices::LOG, [$ts=rec$ts, $uid=rec$uid,
	                             $src=rec$id$orig_h, $domain=m,
	                             $query=rec$query, $signal="dns"]);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	if ( ! rec?$server_name )
		return;

	local m = match_domain(rec$server_name);
	if ( m == "" )
		return;

	Log::write(AIServices::LOG, [$ts=rec$ts, $uid=rec$uid,
	                             $src=rec$id$orig_h, $domain=m,
	                             $query=rec$server_name, $signal="sni"]);
	}
