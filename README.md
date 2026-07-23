# wolfGlass

wolfGlass is the single source of truth for the SBOM tools. Each product
repository vendors a small, pinned subset of these files. wolfGlass also runs the
central advisory tool and the optional build-provenance tool.

This repository now carries the shared SBOM generator, the shared build
fragments, the front ends, the advisory/VEX tooling, and the provenance
verifier. Product repositories vendor the SBOM layer from here.

## Goals

- Make one valid SBOM (CycloneDX 1.6 and SPDX 2.3) for every product.
- Fix a defect one time and let all products get the fix.
- Keep the output reproducible and auditable.
- Run on air-gapped Linux, embedded hosts, and Windows.
- Never modify a FIPS-certified bundle.

## Layout

| Path | Purpose |
|---|---|
| `share/` | The vendorable SBOM driver, front ends, and build fragments. |
| `central/` | Planned home of the advisory/VEX tools. Not vendored. |
| `provenance/` | Planned home of the bomsh provenance tools. Opt-in. |
| `schemas/` | Planned home of pinned offline validation schemas. |
| `tools/` | The sync tool and the future out-of-tree driver. |
| `.github/workflows/` | Repository CI and reusable GitHub workflows. |
| `tests/` | Tool unit tests. Not vendored. |
| `docs/` | The program plan and integration guides. |

## Current State

Present now:

- Shared Python driver: `share/sbom-driver.py` and `share/sbom-driver`
- Shared generator: `share/gen-sbom`
- Shared autotools fragment: `share/sbom.am`
- Shared front ends: `frontends/compdb_sbom.py`, `iar_sbom.py`, `zephyr_sbom.py`
- Shared build fragments for Make, CMake, and autotools
- Central advisory/VEX tooling
- Central provenance verifier
- Sync tool, validator, self-test, and GitHub workflows

Not here yet:

- Offline schema bundle
- Full provenance driver wiring

## Quick start

Vendor the toolkit into a product and generate an SBOM:

```sh
# 1. Copy the shared set into the product at tools/sbom/.
tools/wolfglass-sync --dest /path/to/product

# 2. From the product build, call the driver (or the Make/CMake fragment).
tools/sbom/sbom-driver --name wolfboot --srcs-file srcs.txt \
    --cflags="$CFLAGS" --version-file include/wolfboot/version.h \
    --version-macro LIBWOLFBOOT_VERSION_STRING
```

Run the self-test:

```sh
python3 tests/test_sbom.py
```

## Status

The shared SBOM layer is ready for product adoption now: the product-neutral
engine (`share/`), the vendored generator, the Make/CMake/autotools fragments,
the front ends, the sync tool, the validator, the self-test, and the CI
workflows are in place.

`gen-sbom` now lives in `share/` and is discovered there by default. A product
can still override it with `--gen-sbom` if it needs to pin a different copy for
testing.

The full program plan is in [`docs/PLAN.md`](docs/PLAN.md). The authoritative
product-by-front-end matrix and dictionary are in [`docs/TIERS.md`](docs/TIERS.md).

## License

GPLv3 (see [`LICENSE`](LICENSE)), aligned with the other wolfSSL repositories.
That removes the earlier Apache-vs-GPL question for sharing code with wolfBoot
and wolfSSL.
