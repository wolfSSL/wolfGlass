# central/

These tools run for wolfSSL only. Do not vendor them into a product.

- `gen-advisory` — the CSAF 2.0 and CycloneDX VEX generator.
- `advisory-completeness` — the release gate. It reconciles the CVEs a
  release is supposed to cover against the CVE records and VEX overlay
  entries present, and fails if any are missing:

      python3 central/advisory-completeness --cve-list advisories/releases/5.9.2.cves

      python3 central/advisory-completeness --release 5.9.2 \
          --changelog ../wolfssl/ChangeLog.md

  It checks completeness only; it cannot judge whether a determination is
  correct — that is human analysis. `--cve-list` is the CI path (this repo
  does not contain the product ChangeLog). Count only ChangeLog bullets of
  the form `* [High] CVE-…`; ids named in the paragraph are ignored.
- `csaf-publish` — assemble the `.well-known/csaf` directory (hashes, index,
  provider-metadata, optional OpenPGP signatures). Sign at deploy, not in git.
- `csaf-verify` — consumer-side check of hashes and signatures.
- `advisory-vex-overlay.schema.json` — the per-CVE overlay schema.
- `advisory-vex-overlay.example.json` — an overlay example.

The advisory tool is already multi-product. It keys the PURL and the CPE per
product. The security team makes the advisory from CVE records. No product needs
a build step for advisories.
