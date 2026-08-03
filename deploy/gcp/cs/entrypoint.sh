#!/bin/sh
# Confidential Space runs ONE container. For the demo we run the mock upstream in
# the background and the measured fid-proxy in the foreground (PID 1).
set -e
/app/mock-upstream &
exec /app/fid-proxy
