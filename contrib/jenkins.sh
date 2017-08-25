#!/bin/sh

set -ex

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

mkdir deps || true
cd deps
osmo-deps.sh libosmocore

cd libosmocore
autoreconf --install --force
./configure --prefix=$PWD/../install
$MAKE $PARALLEL_MAKE install

cd ../../

autoreconf --install --force
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig:$PKG_CONFIG_PATH ./configure
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig:$PKG_CONFIG_PATH $MAKE $PARALLEL_MAKE
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig:$PKG_CONFIG_PATH LD_LIBRARY_PATH=$PWD/deps/install/lib $MAKE distcheck
