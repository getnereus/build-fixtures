# syntax=docker/dockerfile:1.12-labs
# RUN --security=insecure needs the security.insecure entitlement, which the build's daemon never receives
# (getnereus/nereus#1091, spec 0009): BuildKit refuses this build before its first step.
FROM busybox:1.37.0
RUN --security=insecure echo "PROBE run-security-insecure ran"
