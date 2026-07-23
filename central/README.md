# central/

These tools run for wolfSSL only. Do not vendor them into a product.

Planned contents (see `docs/PLAN.md`):

- `gen-advisory` — the CSAF 2.0 and CycloneDX VEX generator.
- `advisory-vex-overlay.schema.json` — the per-CVE overlay schema.
- `advisory-vex-overlay.example.json` — an overlay example.

The advisory tool is already multi-product. It keys the PURL and the CPE per
product. The security team makes the advisory from CVE records. No product needs
a build step for advisories.
