# A RUN asks the build egress proxy for a host off its list (getnereus/nereus#1142, spec 0009): the proxy answers 407,
# the build fails, and the Build names example.org; once the build reef's Mandate allows it, the same build succeeds.
# curl, not busybox wget: wget sends an https URL to http_proxy as a plain request, which Smokescreen does not serve;
# curl asks for a CONNECT tunnel, as pip and apk do.
FROM python:3.13-alpine
RUN apk add --no-cache curl
RUN curl -sS -o /dev/null https://example.org/ && echo "PROBE refused-host reached"
CMD ["true"]
