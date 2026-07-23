# wolfGlass

wolfGlass is the single source of truth for the SBOM tools. Each product
repository vendors a small, pinned subset of these files. wolfGlass also runs the
central advisory tool and the optional build-provenance tool.

## Goals

- Make one valid SBOM (CycloneDX 1.6 and SPDX 2.3) for every product.
- Fix a defect one time and let all products get the fix.
- Keep the output reproducible and auditable.
- Run on air-gapped Linux, embedded hosts, and Windows.
- Never modify a FIPS-certified bundle.

## Layout

| Path | Purpose |
|---|---|
| `share/` | The only vendorable set. Products copy these files. |
| `central/` | The advisory tool. Runs for wolfSSL only. Not vendored. |
| `provenance/` | The bomsh provenance tool. Opt-in. Linux only. |
| `schemas/` | Pinned CDX 1.6 and SPDX 2.3 schemas for offline validation. |
| `tools/` | The sync tool and the out-of-tree driver. |
| `.github/workflows/` | Repository CI and reusable GitHub workflows. |
| `tests/` | Tool unit tests. Not vendored. |
| `docs/` | The program plan and integration guides. |

## Quick start

Vendor the toolkit into a product and generate an SBOM:

```sh
# 1. Copy the shared set into the product at tools/sbom/.
tools/wolfglass-sync --dest /path/to/product

# 2. From the product build, call the driver (or the Make/CMake fragment).
#    Point it at a gen-sbom until one is vendored (see Open decisions).
export WOLFSSL_DIR=/path/to/wolfssl
tools/sbom/sbom-driver --name wolfboot --srcs-file srcs.txt \
    --cflags="$CFLAGS" --version-file include/wolfboot/version.h \
    --version-macro LIBWOLFBOOT_VERSION_STRING
```

Run the self-test:

```sh
WOLFSSL_DIR=/path/to/wolfssl python3 tests/test_sbom.py
```

## Status

Phase 1 is complete: the product-neutral engine (`share/`), the front ends, the
build fragments, the sync tool, the self-test, and the CI workflows are in place
and tested. The full program plan is in [`docs/PLAN.md`](docs/PLAN.md). It lists
the problem, the solution, the benefits, the product tiers, the design, the CI
strategy, and the migration phases. The authoritative product-by-front-end
matrix and the dictionary are in [`docs/TIERS.md`](docs/TIERS.md).

The one item that gates full air-gapped use is the generator home: `gen-sbom` is
not vendored yet. The driver discovers it through `--gen-sbom` or `WOLFSSL_DIR`
until that decision is signed off. See "Open decisions" in the plan.

## License

GPLv3 (see [`LICENSE`](LICENSE)), aligned with the other wolfSSL repositories.
That removes the earlier Apache-vs-GPL question for sharing code with wolfBoot
and wolfSSL.
