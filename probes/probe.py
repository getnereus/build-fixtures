"""The hostile probes a build runs (getnereus/nereus#1091, spec 0009 of Nereus, "What the scene of #848 must prove").

Each probe prints one line, `PROBE <name> <result>`, which the scene compares with spec 0009's table. A connection ends
`reached`, `refused`, `dropped` (no answer before the timeout) or `unreachable` (an ICMP refusal): k3s refuses a denied
connection where other policy controllers drop it, so the scene accepts any of the last three as stopped. A name that
does not resolve prints `unresolved`, which proves nothing, so the scene fails on it.

Python's standard library only, so the probes need nothing but the base image."""
import argparse
import errno
import http.client
import os
import re
import socket
import ssl
import struct
import time

TIMEOUT = 4
# What a git token, a push credential or a ServiceAccount token leaves where a RUN can read it. Written in hex so this
# file, which a RUN can read in the build context and in BuildKit's state, does not match itself.
CANARIES = tuple(bytes.fromhex(each) for each in (
  "22617574687322",  # the key of a registry credential's config.json
  "6b756265726e657465732e696f7e736563726574",  # a Secret volume in a mount table
  "6b756265726e657465732e696f7e70726f6a6563746564",  # a ServiceAccount token volume
  "782d6163636573732d746f6b656e",  # a GitHub App token's user name
  "707573682d63726564656e7469616c",  # the push Secret's volume name
))
SECRET_NAMES = re.compile(r"(TOKEN|PASSWORD|SECRET|CREDENTIAL|AUTH)", re.IGNORECASE)
# Folders a file walk skips: the kernel's own trees.
SKIPPED = ("proc", "sys", "dev")
WALK_SECONDS = 120
LARGEST = 1024 * 1024
CONTROL = "/tmp/probe-control"


def say(name: str, result: str) -> None:
  print(f"PROBE {name} {result}", flush=True)


def address_of(host: str) -> str | None:
  if re.fullmatch(r"[0-9.]+", host):
    return host
  try:
    return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
  except socket.gaierror:
    return None


def connect(host: str, port: int) -> str:
  address = address_of(host)
  if address is None:
    return "unresolved"
  try:
    with socket.create_connection((address, port), timeout=TIMEOUT):
      return "reached"
  except ConnectionRefusedError:
    return "refused"
  except TimeoutError:
    return "dropped"
  except OSError as error:
    if error.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM):
      return "unreachable"
    return f"error-{errno.errorcode.get(error.errno, error.errno)}"


def anonymous(host: str, port: int, path: str) -> str:
  """What an anonymous HTTPS GET gets: `status-<code>` when it is answered, else how the connection ended."""
  reached = connect(host, port)
  if reached != "reached":
    return reached
  try:
    answer = http.client.HTTPSConnection(address_of(host), port, timeout=TIMEOUT, context=ssl._create_unverified_context())
    answer.request("GET", path)
    return f"status-{answer.getresponse().status}"
  except (OSError, http.client.HTTPException):
    return "no-answer"


def gateway() -> str:
  """The default route's gateway: in a Pod, its own node."""
  with open("/proc/net/route") as table:
    for line in table.read().splitlines()[1:]:
      fields = line.split()
      if fields[1] == "00000000":
        return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
  return "none"


def network() -> None:
  """Each refused target beside an allowed one."""
  node = gateway()
  say("node-address", node)
  # A Service in another namespace: CoreDNS on 53 is allowed, the same Service's metrics port is not.
  say("service-dns-53", connect("kube-dns.kube-system.svc.cluster.local", 53))
  say("service-dns-9153", connect("kube-dns.kube-system.svc.cluster.local", 9153))
  # A Service and a Pod in another namespace, through Services the scene makes: the registry's namespace is allowed
  # (the push), the buildkit Nereid's in nereus-system is not. probe-pod is headless, so its name is the Pod's address.
  say("service-registry", connect("probe-service.registry-main.svc.cluster.local", 5000))
  say("service-nereid", connect("probe-service.nereus-system.svc.cluster.local", 8080))
  say("pod-registry", connect("probe-pod.registry-main.svc.cluster.local", 5000))
  say("pod-nereid", connect("probe-pod.nereus-system.svc.cluster.local", 8080))
  # The kube-apiserver behind its Service, and the node's own ports: recorded, and anonymous gets no data.
  say("apiserver-service", connect("kubernetes.default.svc.cluster.local", 443))
  say("apiserver-service-anonymous", anonymous("kubernetes.default.svc.cluster.local", 443, "/api/v1/namespaces/builds/secrets"))
  say("node-6443", connect(node, 6443))
  say("node-6443-anonymous", anonymous(node, 6443, "/api/v1/namespaces/builds/secrets"))
  say("node-10250", connect(node, 10250))
  say("node-10250-anonymous", anonymous(node, 10250, "/pods"))
  # A NodePort on the node, the scene's: the documented hole (#1009).
  say("node-nodeport", connect(node, 30910))
  # k3d's registry and the scenes' pull-through caches on Docker's network.
  say("k3d-registry", connect("k3d-nereus-registry.localhost", 5000))
  say("k3d-cache", connect("k3d-nereus-cache-docker", 5000))
  # The public internet: 443 is allowed, another port is not.
  say("public-443", connect("github.com", 443))
  say("public-22", connect("github.com", 22))


def matches(data: bytes) -> list[str]:
  return [each.hex() for each in CANARIES if each in data]


def read(path: str, limit: int = LARGEST) -> bytes | None:
  try:
    with open(path, "rb") as found:
      return found.read(limit)
  except OSError:
    return None


def processes() -> None:
  """Every process a RUN sees, their environment, command lines and mounts, and every file under their roots."""
  pids = [each for each in os.listdir("/proc") if each.isdigit()]
  say("proc-visible", str(len(pids)))
  found_proc, found_mounts, roots = [], [], {}
  for pid in pids:
    for part, found in (("environ", found_proc), ("cmdline", found_proc), ("mountinfo", found_mounts)):
      for each in matches(read(f"/proc/{pid}/{part}") or b""):
        found.append(f"/proc/{pid}/{part}:{each}")
    try:
      root = os.stat(f"/proc/{pid}/root")
    except OSError:
      continue
    roots.setdefault((root.st_dev, root.st_ino), f"/proc/{pid}/root")
  for where in found_proc + found_mounts:
    print(f"FOUND {where}", flush=True)
  say("canary-proc", "found" if found_proc else "none")
  say("canary-mounts", "found" if found_mounts else "none")
  say("proc-roots", str(len(roots)))
  # The positive control: a canary this RUN writes must be found, or a walk that reads nothing would pass.
  with open(CONTROL, "wb") as control:
    control.write(CANARIES[0])
  found_all = walk(["/", *roots.values()])
  found_files = [each for each in found_all if not each.endswith(f"{os.path.basename(CONTROL)}:{CANARIES[0].hex()}")]
  say("canary-control", "found" if len(found_files) < len(found_all) else "none")
  for where in found_files:
    print(f"FOUND {where}", flush=True)
  say("canary-files", "found" if found_files else "none")
  named = sorted(key for key in os.environ if SECRET_NAMES.search(key))
  valued = [key for key, value in os.environ.items() if matches(value.encode())]
  for key in named + valued:
    print(f"FOUND env:{key}", flush=True)
  say("canary-env", "found" if named or valued else "none")
  say("serviceaccount-token", "found" if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token") else "none")


def walk(tops: list[str]) -> list[str]:
  """Files holding a canary under each root, within a time budget; a file seen through two roots counts once."""
  found, seen, deadline = [], set(), time.monotonic() + WALK_SECONDS
  for top in tops:
    for folder, folders, files in os.walk(top):
      if os.path.relpath(folder, top) == ".":
        folders[:] = [each for each in folders if each not in SKIPPED]
      for name in files:
        if time.monotonic() > deadline:
          print("FOUND walk-timeout", flush=True)
          return found
        path = os.path.join(folder, name)
        try:
          status = os.stat(path, follow_symlinks=False)
        except OSError:
          continue
        if not os.path.isfile(path) or os.path.islink(path) or status.st_size > LARGEST or (status.st_dev, status.st_ino) in seen:
          continue
        seen.add((status.st_dev, status.st_ino))
        for each in matches(read(path) or b""):
          found.append(f"{path}:{each}")
  return found


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("group", choices=("network", "processes"))
  arguments = parser.parse_args()
  {"network": network, "processes": processes}[arguments.group]()


if __name__ == "__main__":
  main()
