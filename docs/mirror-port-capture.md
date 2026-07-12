# Building a reliable mirror-port capture path

The Zeek script in this repo is the easy part. The hard part is getting the packets to it — reliably, and in a way that fails loudly instead of silently. This is the capture architecture we run in production, with the landmines called out. All addresses below are examples (`10.20.30.x`).

## The path

```
[ LAN devices ]
      │
[ Aggregation switch ]──port N (uplink to gateway)
      │                      │
      │              port M: Mirroring, source = port N
      │                      │
      │              [ hypervisor capture NIC ]   ← broken OUT of the LACP bond
      │                      │
      │              [ vmbr2: IP-less bridge, bridge-ageing 0 ]
      │                      │
      │              [ sensor container eth1, promiscuous ]
      │                      │
      │              [ Zeek → ai_services.log ]
```

## Rules that came from failures

### 1. Use a real switch mirror port, not a host-side `tc` mirror

Our first capture path used `tc` (`matchall` + `mirred` action) on the hypervisor to copy traffic into the sensor. It worked when built, then silently degraded: `tc` mirrors don't survive interface reconfigurations, reboots, or bridge changes, and nothing tells you they stopped. A capture path that can fail silently *will*, and your inventory quietly becomes fiction. Configure mirroring on the switch, where it's part of persistent switch config.

### 2. Mirror inside the NAT boundary

Do **not** mirror the WAN side of your gateway. That traffic is post-NAT: every flow appears to originate from the gateway, and per-device attribution — the entire point — is lost. Mirror the LAN-side uplink.

### 3. Give capture its own NIC, outside any bond

A NIC that's a member of a LACP bond is not a clean capture NIC — the bond owns it. Break one port out of the bond permanently and dedicate it to capture. Then treat that as load-bearing config: document that it must never be re-added to the bond, because "unused NIC, let's re-bond it" is exactly what a future cleanup pass will want to do.

### 4. `bridge-ageing 0` on the capture bridge — this is the big one

The capture NIC connects to the sensor container through an IP-less Linux bridge. A default Linux bridge is a *learning* bridge: it observes source MACs and then forwards frames only toward the port where each destination MAC lives. Mirrored traffic breaks this assumption — the bridge learns MACs from the mirrored frames on the capture-NIC side, concludes the destinations live there, and **stops flooding frames to the sensor port**. The sensor goes quiet minutes after boot while every piece of config looks correct.

`bridge-ageing 0` disables MAC learning expiry-based forwarding and forces flood-always behavior. See `examples/interfaces`:

```
auto vmbr2
iface vmbr2 inet manual
    bridge-ports enp5s0f3
    bridge-stp off
    bridge-fd 0
    bridge-ageing 0
```

### 5. The sensor interface must be promiscuous

The mirrored frames are addressed to other hosts' MACs. The sensor's capture interface (`eth1` here) must be in promiscuous mode or the kernel drops them before Zeek sees anything. Zeek's `node.cfg` points at that interface — see `examples/node.cfg`.

### 6. Size Zeek's memory for mirror load, and monitor the process

A sensor that was fine watching its own host's traffic will not be fine watching a whole LAN. Ours ran Zeek in a container with a 1 GB memory limit; under full mirror load (~730 packets/second in our environment) Zeek crashed OOM — while the log forwarder next to it kept publishing heartbeats, so the pipeline looked alive. We run 4 GB now. Monitor the Zeek *process*, not just the pipeline: a healthy forwarder in front of a dead Zeek is the most convincing lie your monitoring will ever tell you.

## Verifying the path

1. `tcpdump -i eth1 -c 20` in the sensor — you should see traffic *between other hosts*, not just your own.
2. Check `ssl.log` populates with `server_name` (SNI) values. An empty `ssl.log` is a visibility question before it is a configuration question — if the sensor can't see TLS traffic, there's nothing to log.
3. Generate a known signal: from a workstation (not the hypervisor), open an AI service, and watch for the hit in `ai_services.log` with that workstation's IP. End-to-end attribution within minutes is the acceptance test.
