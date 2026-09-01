# Generic Environment Discovery

`EnvironmentDiscoveryService` collects provider-neutral observations from
local applications/services/devices, USB, Bluetooth/BLE, mDNS/DNS-SD, SSDP,
and safe advertisements. Providers are injected; there are no
product-specific discovery handlers.

Modes are explicit:

- `PASSIVE_DISCOVERY` consumes advertisements and already-available signals.
- `READ_ONLY_LOCAL_DISCOVERY` reads local inventories without mutation.
- `ACTIVE_DISCOVERY` may probe, but requires a stronger application policy.

Passive discovery is the default. The service never performs aggressive scans
implicitly. A denied active probe fails closed before the provider is called.

## Evidence contract

`DiscoveryObservation` records source, timestamp, typed identity identifiers,
bounded properties, classification, origin, first/last-seen times, provenance,
and confidence. `EnvironmentCandidate` deduplicates observations by stable
identity while retaining source evidence. Staleness is explicit and cleanup
removes only the in-memory observation projection.

External metadata is retained as untrusted data. Discovery cannot authenticate,
trust, install, grant authority, declare ownership, or alter permission policy.
Malformed/control-bearing metadata fails closed. Candidate sink callbacks emit
generic evidence for the future Opportunity Engine; they are not approval or
execution requests.
