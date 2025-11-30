#!/usr/bin/env sh

while true; do
	  echo "$(date)" "  Starting Foghorn:"
	  echo "==================================="
	  foghorn --config /foghorn/config/config.yaml || break
	  echo "$(date)""  Foghorn. Stopped."
	  echo "==================================="
	  echo
	  sleep 1
done

echo "Foghorn ended"
