
# Foghorn + Bind9 AXFR downstream test

This directory contains:

- A Foghorn configuration (`foghorn_axfr_client.yaml`) that serves `axfr-test.test` authoritatively from the local BIND-style zone file `zones/db.axfr-test.test` using the `zone`/`zone_records` plugin via `bind_paths`.
- A Bind9 configuration (`named.conf`) that configures `axfr-test.test` as a slave zone and AXFRs it from the Foghorn server on TCP port 5360.

Typical flow:

1. Start Foghorn from the repo root, pointing at this config:

   `foghorn --config example_configs/bind/axfr_downstream/foghorn_axfr_client.yaml`

2. Build and run Bind9 from this directory (for example, using host networking so it can reach Foghorn on 127.0.0.1:5360):

   `docker build -t bind9-axfr-downstream .`

   `docker run --rm --network host --name bind9-axfr-downstream bind9-axfr-downstream`

3. Verify that Bind9 has AXFR'd the zone from Foghorn:

   `dig @127.0.0.1 -p 53 axfr axfr-test.test`
