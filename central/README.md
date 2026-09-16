# central/

These tools run for wolfSSL only. Do not vendor them into a product.

- `gen-advisory` — the CSAF 2.0 and CycloneDX VEX generator.
- `advisory-completeness` — the release gate. It reconciles the CVEs a
  release is supposed to cover against the CVE records and VEX overlay
  entries present, and fails if any are missing:

      python3 central/advisory-completeness --cve-list advisories/releases/5.9.2.cves \
          --release 5.9.2 \
          --changelog central/testdata/ChangeLog-5.9.2.md \
          --prior-release advisories/releases/5.9.2.prior-release.cves \
          --mentions advisories/releases/5.9.2.mentions.cves \
          --require-fixed-version 5.9.2

      python3 central/advisory-completeness --release 5.9.2 \
          --changelog ../wolfssl/ChangeLog.md

  It checks completeness only; it cannot judge whether a determination is
  correct — that is human analysis. `--cve-list` is the CI path (this repo
  does not contain the product ChangeLog). Count ChangeLog bullets of the
  form `* [High] CVE-…` as members. The tool also computes a loose set of
  every CVE id in the Vulnerabilities section and fails if the strict rule
  dropped an id that is not listed in `--mentions`. `--release` must match
  the CVE-list filename stem when both flags are set.
- `csaf-publish` — assemble the `.well-known/csaf` directory (hashes, index,
  provider-metadata, optional OpenPGP signatures via pgpy). Sign at deploy,
  not in git. Honors `SOURCE_DATE_EPOCH`.
- `csaf-verify` — consumer-side check. Walks `index.txt` and hash sidecars.
  Signature checks require `--fingerprint` matching provider-metadata.json.
- `advisory-vex-overlay.schema.json` — the per-CVE overlay schema.
- `advisory-vex-overlay.example.json` — an overlay example.

The advisory tool is already multi-product. It keys the PURL and the CPE per
product. The security team makes the advisory from CVE records. No product needs
a build step for advisories.
