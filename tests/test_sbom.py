#!/usr/bin/env python3
"""wolfGlass self-test.

Two layers:

  * Unit tests always run. They need no gen-sbom. They cover the path scrub, the
    version parser, and the structural validator.
  * Integration tests run when gen-sbom is found (vendored, via --gen-sbom,
    GEN_SBOM, or WOLFSSL_DIR). They cover a full generate for the source-embedded and the
    library paths, the path-scrub end to end, and byte-reproducibility.

Usage:
  tests/test_sbom.py [--gen-sbom PATH]
  GEN_SBOM=/path/to/gen-sbom tests/test_sbom.py
  python3 tests/test_sbom.py
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARE = os.path.join(REPO, "share")
DRIVER = os.path.join(SHARE, "sbom-driver")
VALIDATE = os.path.join(SHARE, "validate_sbom.py")

_fail = 0


def check(cond, msg):
    global _fail
    if cond:
        print(f"  ok: {msg}")
    else:
        print(f"  FAIL: {msg}", file=sys.stderr)
        _fail += 1


def load_driver_module():
    spec = importlib.util.spec_from_file_location(
        "sbom_driver", os.path.join(SHARE, "sbom-driver.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def unit_tests():
    print("[unit] scrub / version / validate")
    drv = load_driver_module()

    scrubbed = drv.scrub_defines(
        '#define PICO_SDK_PATH "/home/secret/pico-sdk"\n'
        '#define HAVE_AES 1\n')
    check("secret" not in scrubbed, "scrub removes absolute path")
    check("PICO_SDK_PATH" in scrubbed, "scrub keeps the macro name")
    check("HAVE_AES 1" in scrubbed, "scrub keeps non-path macros")

    with tempfile.TemporaryDirectory() as d:
        vh = os.path.join(d, "version.h")
        with open(vh, "w") as f:
            f.write('#define LIBWOLFBOOT_VERSION_STRING "2.4.0"\n')
        check(drv.read_version(vh, "LIBWOLFBOOT_VERSION_STRING") == "2.4.0",
              "version parser reads the macro")
        check(drv.read_version(vh, "NOPE") == "", "version parser misses cleanly")

    # capture_macros must tokenise CFLAGS with shlex, not str.split, so a
    # quoted spaced -D value survives as one define instead of being torn
    # apart. Needs a host compiler; skip cleanly when none is present.
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc:
        out = drv.capture_macros(cc, '-DHAVE_AES -DWG_BANNER="a b c"')
        check("#define HAVE_AES" in out, "capture_macros keeps a plain -D")
        check("#define WG_BANNER a b c" in out,
              "capture_macros preserves a quoted spaced -D value")
    else:
        print("  skip: no host cc for capture_macros test")

    # Validator: a good CycloneDX passes with the right prefix; a wrong prefix
    # fails.
    with tempfile.TemporaryDirectory() as d:
        good = os.path.join(d, "x.cdx.json")
        with open(good, "w") as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6",
                       "metadata": {"component": {"name": "wolftpm",
                                                  "version": "3.9.0",
                                                  "properties": [{"a": "b"}]}}},
                      f)
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--name-prefix", "wolftpm", good],
                             stdout=subprocess.DEVNULL)
        check(rc == 0, "validator accepts a good CycloneDX")
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--name-prefix", "wolfssh", good],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check(rc != 0, "validator rejects a wrong name prefix")


def find_gen_sbom(explicit):
    if explicit and os.path.isfile(explicit):
        return explicit
    env = os.environ.get("GEN_SBOM")
    if env and os.path.isfile(env):
        return env
    vendored = os.path.join(SHARE, "gen-sbom")
    if os.path.isfile(vendored):
        return vendored
    wd = os.environ.get("WOLFSSL_DIR")
    if wd:
        cand = os.path.join(wd, "scripts", "gen-sbom")
        if os.path.isfile(cand):
            return cand
    return None


def run_driver(workdir, gen_sbom, extra):
    cmd = [DRIVER, "--name", "selftest", "--version", "1.0.0",
           "--license-file", os.path.join(workdir, "LICENSE"),
           "--gen-sbom", gen_sbom, "--root", workdir] + extra
    return subprocess.run(cmd, cwd=workdir, capture_output=True, text=True)


def integration_tests(gen_sbom):
    print(f"[integration] gen-sbom = {gen_sbom}")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "LICENSE"), "w") as f:
            f.write("MIT License\n")
        a = os.path.join(d, "a.c")
        b = os.path.join(d, "b.c")
        for p in (a, b):
            with open(p, "w") as f:
                f.write("int f(void){return 0;}\n")
        srcs = os.path.join(d, "srcs.txt")
        with open(srcs, "w") as f:
            f.write(a + "\n" + b + "\n")

        # Source-embedded path with a path-valued define.
        r = run_driver(d, gen_sbom, [
            "--srcs-file", srcs,
            "--cflags=-DHAVE_AES -DPICO_SDK_PATH=/home/secret/sdk",
            "--cdx-out", "e.cdx.json", "--spdx-out", "e.spdx.json"])
        check(r.returncode == 0, "source-embedded generate succeeds")
        cdx = os.path.join(d, "e.cdx.json")
        check(os.path.isfile(cdx), "CycloneDX written")
        check(os.path.isfile(os.path.join(d, "e.spdx.json")), "SPDX written")
        if os.path.isfile(cdx):
            text = open(cdx).read()
            check("secret" not in text, "no host path leaks into the SBOM")
            check("PICO_SDK_PATH" in text, "config macro name retained")
            rc = subprocess.call([sys.executable, VALIDATE,
                                  "--name-prefix", "selftest", cdx],
                                 stdout=subprocess.DEVNULL)
            check(rc == 0, "generated CycloneDX validates")

        # Library path (tier R/L/S): hash a built artifact.
        lib = os.path.join(d, "libselftest.a")
        with open(lib, "wb") as f:
            f.write(b"!<arch>\n" + b"\x00" * 64)
        r = run_driver(d, gen_sbom, [
            "--lib", lib, "--cflags=-DHAVE_AES",
            "--cdx-out", "l.cdx.json", "--spdx-out", "l.spdx.json"])
        check(r.returncode == 0, "library generate succeeds")

        # Reproducibility: same inputs + SOURCE_DATE_EPOCH => byte-identical.
        env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
        outs = []
        for i in (1, 2):
            cmd = [DRIVER, "--name", "selftest", "--version", "1.0.0",
                   "--license-file", os.path.join(d, "LICENSE"),
                   "--gen-sbom", gen_sbom, "--root", d,
                   "--srcs-file", srcs, "--cflags=-DHAVE_AES",
                   "--cdx-out", f"r{i}.cdx.json", "--spdx-out", f"r{i}.spdx.json"]
            subprocess.run(cmd, cwd=d, env=env, capture_output=True, text=True)
            p = os.path.join(d, f"r{i}.cdx.json")
            outs.append(open(p).read() if os.path.isfile(p) else f"<missing {i}>")
        check(outs[0] == outs[1], "byte-reproducible CycloneDX")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen-sbom", default="")
    args = ap.parse_args()

    unit_tests()
    gen_sbom = find_gen_sbom(args.gen_sbom)
    if gen_sbom:
        integration_tests(gen_sbom)
    else:
        print("[integration] SKIP: gen-sbom not found "
              "(vendored copy missing; set GEN_SBOM or WOLFSSL_DIR)")

    if _fail:
        print(f"\n{_fail} check(s) FAILED", file=sys.stderr)
        sys.exit(1)
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
