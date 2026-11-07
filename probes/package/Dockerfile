# A RUN installs packages through the build egress proxy (getnereus/nereus#1142, spec 0009): BuildKit passes HTTPS_PROXY
# to every RUN, and dl-cdn.alpinelinux.org and pypi.org are on the proxy's default list.
FROM python:3.13-alpine
RUN apk add --no-cache jq && echo "PROBE package-apk installed"
RUN pip install --quiet --no-cache-dir --root-user-action=ignore six==1.17.0 && echo "PROBE package-pip installed"
CMD ["true"]
