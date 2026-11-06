# The build reef's scene app (getnereus/nereus#1067): the smallest HTTP server, so a build pulls little.
FROM busybox:1.37.0
COPY index.html /www/index.html
EXPOSE 8080
USER 65534
CMD ["httpd", "-f", "-v", "-p", "8080", "-h", "/www"]
