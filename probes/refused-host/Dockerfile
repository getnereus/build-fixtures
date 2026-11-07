# A RUN asks the build egress proxy for a host off its list (getnereus/nereus#1142, spec 0009): the proxy answers 407,
# the build fails, and the Build names example.org; once the build reef's Mandate allows it, the same build succeeds.
FROM python:3.13-alpine
RUN wget -q -T 10 -O /dev/null https://example.org/ && echo "PROBE refused-host reached"
CMD ["true"]
