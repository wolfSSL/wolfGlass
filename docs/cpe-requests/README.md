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
| wolfBoot | `wolfssl` | registered | `cpe:2.3:a:wolfssl:wolfboot:<ver>:*:*:*:*:*:*:*` |

All products in the table are registered in the NVD Official CPE Dictionary.
`gen-sbom` emits the main-package `cpe` field for each.

The wolfcrypt CPE stays in the dictionary. Nested wolfcrypt components do
**not** emit it: NVD files crypto CVEs against `wolfssl`, not `wolfcrypt`,
and a second CPE on the same sources is a future double-match risk.
Matching rides on `cpe:2.3:a:wolfssl:wolfssl:<version>`. The unique id for
the nested library is the PURL (`pkg:github/wolfssl/wolfssl@v<ver>-stable#wolfcrypt`).

## Pending products (none today)

A product with `status: pending` emits **no `cpe` field**. A scanner cannot
tell an unlisted CPE from a listed one that simply has no advisories, so
publishing the string asserts a dictionary match that does not exist. Until
NVD lists the name, the SBOM records the intended identifier out of band:

| Field | Value |
| --- | --- |
| `wolfssl:sbom:cpe-status` | `pending` |
| `wolfssl:sbom:cpe-requested` | the exact CPE 2.3 string intended for NIST |

CycloneDX carries the pair as component properties; SPDX carries it as package
annotations and omits the `cpe23Type` external reference. Once NVD publishes
the entry, flip `status` to `registered`: the `cpe` field appears and those
two properties disappear on the next regeneration.

## How to request a new CPE

1. Confirm the product is absent: [NVD CPE search](https://nvd.nist.gov/products/cpe/search).
2. Choose vendor/product to match existing wolfSSL entries (`wolfssl` vendor
   unless NVD already uses a different one, as with wolfSSH).
3. Add a `PRODUCT_CPE` row in `share/gen-sbom` with `status: pending`.
4. Prepare a short product note (facts + why a separate CPE) and CPE Dictionary
   XML under this directory (`<product>.md` / `<product>.xml`).
5. Email `cpe_dictionary@nist.gov` with the XML and product references
   (homepage, GitHub, release tags). Record the send date in the product note;
   do not claim “pending inclusion” until the mail has actually gone.
6. When NVD publishes the entry, flip `status` from `pending` to `registered`
   in `PRODUCT_CPE`, re-vendor products, and remove the request pack for that
   product from this directory.
