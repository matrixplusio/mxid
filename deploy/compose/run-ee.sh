#!/bin/sh
# Launch the freshly-built EE binary with the CE repo as its working directory.
#
# app.Run() resolves several paths relative to CWD — the migrations source
# (`file://migrations`, see internal/bootstrap/migration.go) and the default
# config dir (`configs`). Those live in the CE repo (/workspace/mxid), while the
# EE binary is built under /workspace/mxid-ee. Running from /workspace/mxid makes
# every relative path resolve exactly as it does for the CE dev build.
set -e
cd /workspace/mxid
exec /workspace/mxid-ee/tmp/mxid-ee -config configs
