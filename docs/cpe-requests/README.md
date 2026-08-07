# CPE dictionary requests

NVD matches vulnerabilities by CPE. wolfSSL products that lack an Official CPE
Dictionary entry cannot be found by a CPE-driven CRA / IEC 62443 scanner even
when the SBOM is otherwise correct.

## Current policy (`gen-sbom` `PRODUCT_CPE`)

| Product | Vendor | Status | CPE form |
| --- | --- | --- | --- |
| wolfSSL | `wolfssl` | registered | `cpe:2.3:a:wolfssl:wolfssl:<ver>:*:*:*:*:*:*:*` |
| wolfCrypt | `wolfssl` | registered | `cpe:2.3:a:wolfssl:wolfcrypt:<ver>:*:*:*:*:*:*:*` |
| wolfMQTT | `wolfssl` | registered | `cpe:2.3:a:wolfssl:wolfmqtt:<ver>:*:*:*:*:*:*:*` |
| wolfSSH | `wolfssh` | registered | `cpe:2.3:a:wolfssh:wolfssh:<ver>:*:*:*:*:*:*:*` |
| wolfBoot | `wolfssl` | **pending** | `cpe:2.3:a:wolfssl:wolfboot:<ver>:*:*:*:*:*:*:*` |

A pending product emits **no `cpe` field**. A scanner cannot tell an unlisted
CPE from a listed one that simply has no advisories, so publishing the string
asserts a dictionary match that does not exist. The SBOM records the submitted
identifier out of band instead:

| Field | Value |
| --- | --- |
| `wolfssl:sbom:cpe-status` | `pending` |
| `wolfssl:sbom:cpe-requested` | the exact CPE 2.3 string sent to NIST |

That keeps the document and the submission byte-identical without claiming
registration. CycloneDX carries the pair as component properties; SPDX carries
it as package annotations and omits the `cpe23Type` external reference.

## How to request a new CPE

1. Confirm the product is absent: [NVD CPE search](https://nvd.nist.gov/products/cpe/search).
2. Choose vendor/product to match existing wolfSSL entries (`wolfssl` vendor
   unless NVD already uses a different one, as with wolfSSH).
3. Prepare CPE Dictionary XML (see `wolfboot.xml` for a template).
4. Email `cpe_dictionary@nist.gov` with the XML and product references
   (homepage, GitHub, release tags).
5. When NVD publishes the entry, flip `status` from `pending` to `registered`
   in `share/gen-sbom` `PRODUCT_CPE`. The `cpe` field then appears and the two
   pending properties disappear on the next regeneration; no other change is
   needed.

## Adding another product later

1. Add a `PRODUCT_CPE` row with `status: pending`.
2. Copy `wolfboot.xml` / `wolfboot.md`, rename, and fill product facts.
3. Submit to NIST; promote to `registered` when published.
