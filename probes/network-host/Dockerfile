# RUN --network=host needs the network.host entitlement, which the build's daemon never receives (getnereus/nereus#1091,
# spec 0009): BuildKit refuses this build before its first step.
FROM busybox:1.37.0
RUN --network=host echo "PROBE run-network-host ran"
