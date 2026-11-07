# build-fixtures

The Dockerfiles the scenes of [Nereus](https://github.com/getnereus/nereus) build inside a cluster, with the build reef (getnereus/nereus#1067). Public so a build clones them with no credential.

- `hello/`: the smallest HTTP server, busybox httpd serving one page.
- `probes/`: the hostile `RUN`s of the build reef's security scene (getnereus/nereus#1091, spec 0009): each prints `PROBE <name> <result>` for the scene to compare with the spec's table. `network-host/` and `insecure/` ask for an entitlement the daemon never grants, so BuildKit refuses them; `deadline/` sleeps past a short deadline; `package/` installs an Alpine and a PyPI package through the build egress proxy, and `refused-host/` asks it for a host off its list (getnereus/nereus#1142).
