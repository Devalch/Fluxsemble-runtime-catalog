# Public Pi producer policy data

The supported-contracts-v1.json bytes are the public consumer contract profile
from Fluxsemble commit `6759bb6644ac13b8e23e1c0d27c413c8b0a662e7`, SHA-256
`82d2ab10c550bd2f8ec1a4f5a2513f19332ad3f52729d0f14f1bc7647624d704`.
Its serialization is JCS followed by one LF. This import does not constitute
successful qualification or signed-catalog trust.

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
