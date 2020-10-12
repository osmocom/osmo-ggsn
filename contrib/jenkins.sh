#!/usr/bin/env bash
# jenkins build helper script for openbsc.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * GTP: configure GTP tunneling Linux kernel (values: "--enable-gtp-linux" or "--disable-gtp-linux")
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
#

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

if [ "x$GTP" == "x--enable-gtp-linux" ]; then
	osmo-build-dep.sh libgtpnl
fi
osmo-build-dep.sh libosmocore "" ac_cv_path_DOXYGEN=false

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

# Additional configure options and depends
CONFIG=""
if [ "$WITH_MANUALS" = "1" ]; then
	osmo-build-dep.sh osmo-gsm-manuals
	CONFIG="--enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== OsmoGGSN ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-werror $GTP $CONFIG
$MAKE $PARALLEL_MAKE
DISTCHECK_CONFIGURE_FLAGS="$CONFIG" $MAKE $PARALLEL_MAKE distcheck

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/doc/manuals" publish
fi

$MAKE $PARALLEL_MAKE maintainer-clean
osmo-clean-workspace.sh
