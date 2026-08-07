# CPE request: wolfBoot

## Status

**Pending NVD Official CPE Dictionary inclusion.**

Proposed CPE 2.3:

```
cpe:2.3:a:wolfssl:wolfboot:<version>:*:*:*:*:*:*:*
```

Example for the 2.9.0 release:

```
cpe:2.3:a:wolfssl:wolfboot:2.9.0:*:*:*:*:*:*:*
```

Until NVD lists the product, `gen-sbom` publishes **no `cpe` field** for
wolfBoot. It records the string above as `wolfssl:sbom:cpe-requested`
alongside `wolfssl:sbom:cpe-status=pending`, so the SBOM never asserts a
dictionary match it does not have while still pinning the exact identifier
this request asks for.

## Product facts

| Field | Value |
| --- | --- |
| Title | wolfSSL wolfBoot |
| Vendor | wolfSSL Inc. |
| Product | wolfBoot |
| Part | Application (`a`) |
| Homepage | https://www.wolfssl.com/products/wolfboot/ |
| Source | https://github.com/wolfSSL/wolfBoot |
| Licence | GPL-3.0-or-later (commercial options available) |
| Description | Secure bootloader for embedded systems; verifies and loads signed firmware images. |

## Why a separate CPE

wolfBoot is a firmware product, not the wolfSSL TLS library. Advisories and
scans that key only on `cpe:2.3:a:wolfssl:wolfssl` miss bootloader-specific
issues. A dedicated `wolfssl:wolfboot` CPE lets CRA / IEC 62443 monitoring
match the bootloader the same way `wolfcrypt` and `wolfmqtt` already do.

## Submission

1. Attach `wolfboot.xml` (this directory).
2. Email to **cpe_dictionary@nist.gov**.
3. Include links: homepage, GitHub releases / tags (`v2.9.0`, …).
4. After publication, set `PRODUCT_CPE['wolfboot']['status'] = 'registered'`
   in `share/gen-sbom` and re-vendor products.

## Versions to list initially

Request at least:

- `cpe:2.3:a:wolfssl:wolfboot:-:*:*:*:*:*:*:*` (product base / ANY)
- `cpe:2.3:a:wolfssl:wolfboot:2.9.0:*:*:*:*:*:*:*`

Add further release versions as needed when publishing advisories.
