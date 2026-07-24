# sbom.mk - shared plain-Make fragment for wolfGlass SBOM generation.
#
# One driver does the work; each product describes itself with a few variables
# and includes this fragment to get an `sbom` target. It is the plain-Make
# counterpart of sbom.am (autotools) and sbom.cmake (CMake). All three call the
# same driver, so the three build systems emit byte-comparable SBOMs.
#
# The including Makefile MUST set, before `include .../build/sbom.mk`:
#   SBOM_NAME        Product name recorded in the SBOM (e.g. wolfboot).
#
# Composition - set at least one:
#   SBOM_SRCS        Source files compiled into the artifact (tier E), e.g.:
#                      SBOM_SRCS := $(patsubst %.o,%.c,$(OBJS))
#   SBOM_LIB         Path to the built library to hash (tier R/L/S).
#
# Config - set one:
#   SBOM_CFLAGS      Build CFLAGS whose -D tokens describe the config.
#   SBOM_OPTIONS_H   A pre-expanded flat #define header.
#   SBOM_USER_SETTINGS  A user_settings.h.
#   SBOM_SOURCE_ONLY = 1   Source-inventory SBOM with no build-config macros.
#
# Version - set one:
#   SBOM_VERSION         Literal version string, OR
#   SBOM_VERSION_FILE +  Header to read and the macro to read from it, e.g.:
#   SBOM_VERSION_MACRO     SBOM_VERSION_FILE  = include/wolfboot/version.h
#                          SBOM_VERSION_MACRO = LIBWOLFBOOT_VERSION_STRING
#
# Optional (defaults shown):
#   SBOM_ROOT             Product root. Default: current directory.
#   SBOM_LICENSE_FILE     License file. Default: $(SBOM_ROOT)/LICENSE.
#   SBOM_GEN              Path to gen-sbom. Default: driver auto-discovery.
#   SBOM_NO_ARTIFACT_HASH = 1   As-built FIPS/kernel: do not re-hash.
#   SBOM_DEP_WOLFSSL      yes/no - record wolfSSL as a dependency.
#   SBOM_DEP_OPENSSL      yes/no - record OpenSSL as a dependency.
#   HOSTCC                Host C compiler for macro capture. Default: cc.
#   CRA_PYTHON            Python interpreter. Default: python3.
#
# The driver path is derived from this fragment's own location, so a product
# that vendors share/ into tools/sbom/ needs no path configuration.

SBOM_MK_DIR   := $(dir $(lastword $(MAKEFILE_LIST)))
SBOM_DRIVER   ?= $(abspath $(SBOM_MK_DIR)/../sbom-driver)

SBOM_ROOT     ?= $(CURDIR)
SBOM_LICENSE_FILE ?= $(SBOM_ROOT)/LICENSE
HOSTCC        ?= cc

.PHONY: sbom
sbom:
	@test -n "$(SBOM_NAME)" || { echo "ERROR: set SBOM_NAME"; exit 1; }
	@test -n "$(strip $(SBOM_SRCS))$(SBOM_LIB)" || \
	    { echo "ERROR: set SBOM_SRCS or SBOM_LIB"; exit 1; }
	@set -e; \
	_sf=""; \
	if [ -n "$(strip $(SBOM_SRCS))" ]; then \
	    _sf=`mktemp $${TMPDIR:-/tmp}/wolfglass-srcs.XXXXXX`; \
	    trap 'rm -f "$$_sf"' EXIT INT TERM HUP; \
	    for _s in $(SBOM_SRCS); do echo "$$_s"; done > "$$_sf"; \
	fi; \
	CRA_PYTHON="$(CRA_PYTHON)" HOSTCC="$(HOSTCC)" \
	"$(SBOM_DRIVER)" \
	    --name "$(SBOM_NAME)" \
	    --root "$(SBOM_ROOT)" \
	    --license-file "$(SBOM_LICENSE_FILE)" \
	    --skip-missing \
	    $(if $(strip $(SBOM_SRCS)),--srcs-file "$$_sf") \
	    $(if $(SBOM_LIB),--lib "$(SBOM_LIB)") \
	    $(if $(filter 1,$(SBOM_NO_ARTIFACT_HASH)),--no-artifact-hash) \
	    $(if $(filter 1,$(SBOM_SOURCE_ONLY)),--source-only) \
	    $(if $(SBOM_CFLAGS),--cflags="$(SBOM_CFLAGS)") \
	    $(if $(SBOM_OPTIONS_H),--options-h "$(SBOM_OPTIONS_H)") \
	    $(if $(SBOM_USER_SETTINGS),--user-settings "$(SBOM_USER_SETTINGS)") \
	    $(if $(SBOM_VERSION),--version "$(SBOM_VERSION)") \
	    $(if $(SBOM_VERSION_FILE),--version-file "$(SBOM_VERSION_FILE)") \
	    $(if $(SBOM_VERSION_MACRO),--version-macro "$(SBOM_VERSION_MACRO)") \
	    $(if $(filter yes,$(SBOM_DEP_WOLFSSL)),--dep-wolfssl yes) \
	    $(if $(filter yes,$(SBOM_DEP_OPENSSL)),--dep-openssl yes) \
	    $(if $(SBOM_GEN),--gen-sbom "$(SBOM_GEN)") \
	    $(if $(SBOM_CDX_OUT),--cdx-out "$(SBOM_CDX_OUT)") \
	    $(if $(SBOM_SPDX_OUT),--spdx-out "$(SBOM_SPDX_OUT)")
