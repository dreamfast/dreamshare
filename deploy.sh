#!/bin/sh
# Verifies the container actually came up and is serving.
set -e

IMAGE="${1:-dreamshare}"
PORT="${2:-8080}"
TIMEOUT=30

echo "waiting for port $PORT..."
i=0
while [ $i -lt $TIMEOUT ]; do
    if curl -sf "http://127.0.0.1:$PORT/healthz" > /dev/null 2>&1; then
        echo "healthz ok"
        curl -sf "http://127.0.0.1:$PORT/readyz" > /dev/null 2>&1 && echo "readyz ok" || {
            echo "readyz failed, storage or db not ready"
            exit 1
        }
        echo "container is up and serving"
        exit 0
    fi
    sleep 1
    i=$((i+1))
done

echo "container did not come up within ${TIMEOUT}s"
docker logs --tail 20 "$IMAGE" 2>/dev/null || true
exit 1
