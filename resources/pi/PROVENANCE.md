# Public Pi producer policy data

The supported-contracts-v1.json bytes are the independently admitted public
manifest already present in catalog-acquire's Pi installer fixture. SHA-256:
`3fb5c10c327b14a8537b1a748961ca034d8685ac71f20132ee5039b12b315747`.
Its serialization is JCS followed by one LF. The behavioral profile is independent
of Pi versions, archives, package count, and the tested application's binary hashes.

The explicit consumer requirement in consumer-policy-v1.json is imported from
the reviewed Fluxsemble input-only receipt at product commit `4d6c362`,
`crates/harness-pi/tests/fixtures/pi-1.2.0/inputs/receipt.json`, SHA-256
`65837d21e8f2aafbe889e3a885a81e8aababecfeae1f324fbb8c2c2683bcb2c5`.
This is public policy data, not inferred from this repository's package version.
It does not constitute successful qualification or signed-catalog trust.

The wizard embeds these local data files for new schema-2 generation. Selected
policy is retained in the versioned intent and qualification request; resumed
work uses that exact selection. A future policy update requires an explicit
public-data import. No build, test, or runtime reads the Fluxsemble checkout.
