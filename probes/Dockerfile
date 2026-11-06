# syntax=docker/dockerfile:1.12-labs
# The hostile RUNs of the build reef's scene (getnereus/nereus#1091, spec 0009): each RUN prints `PROBE <name> <result>`
# and never fails on a result, so the scene reads every line in the build container's log and compares it with the
# spec's table. The labs syntax is for RUN --security, the same frontend as insecure/.
FROM python:3.13-alpine
COPY probe.py /probes/probe.py
RUN python3 /probes/probe.py network
RUN python3 /probes/probe.py processes
# The entitlements: the default network and the sandbox run here; host and insecure fail in their own folders, since
# BuildKit refuses the whole build before its first step.
RUN --network=default echo "PROBE run-network-default ran"
RUN --security=sandbox echo "PROBE run-security-sandbox ran"
CMD ["true"]
