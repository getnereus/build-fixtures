# A build that runs past its deadline (getnereus/nereus#1091, spec 0009): the scene sets a short BUILD_DEADLINE_SECONDS,
# and the Job is killed once, never retried.
FROM busybox:1.37.0
RUN echo "PROBE deadline sleeping" && sleep 3600
