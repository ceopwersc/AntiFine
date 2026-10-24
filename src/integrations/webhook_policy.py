"""Allowlisted HTTPS webhooks with validated, pinned public addresses."""
import http.client
import ipaddress
import json
import os
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from src.services.secret_boundary import sanitize_text


@dataclass(frozen=True)
class Destination:
    host: str
    port: int
    path: str
    address: str


def validate_destination(url: str) -> Destination:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Webhook requires credential-free HTTPS; configure credentials outside AntiFine")
    if len(url) > 2048 or sanitize_text(url) != url:
        raise ValueError("Webhook URLs must not contain credentials")
    host = parsed.hostname.lower().rstrip(".")
    allowlist = {x.strip().lower().rstrip(".") for x in os.getenv("ANTIFINE_WEBHOOK_ALLOWLIST", "").split(",") if x.strip()}
    if host not in allowlist:
        raise ValueError("Webhook host is not in ANTIFINE_WEBHOOK_ALLOWLIST")
    port = parsed.port or 443
    if port != 443:
        raise ValueError("Webhook port must be 443")
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = {a[4][0] for a in answers}
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("Webhook must resolve exclusively to public addresses")
    return Destination(host, port, parsed.path or "/", sorted(addresses)[0])


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, destination: Destination):
        super().__init__(destination.host, destination.port, timeout=3, context=ssl.create_default_context())
        self.destination = destination

    def connect(self):
        # Connect to the exact validated IP, retaining certificate/hostname checks.
        sock = socket.create_connection((self.destination.address, self.destination.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.destination.host)


def deliver(url: str, payload: dict) -> None:
    destination = validate_destination(url)  # validate again at send time
    body = json.dumps(payload).encode()
    if len(body) > 64 * 1024:
        raise ValueError("Webhook payload quota exceeded")
    connection = PinnedHTTPSConnection(destination)
    try:
        connection.request("POST", destination.path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError("Webhook rejected delivery")
        response.read(1024)
    finally:
        connection.close()
