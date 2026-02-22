"""
Interactsh/Client.py — Async client for projectdiscovery interactsh-compatible servers.

Handles:
  - Registration (RSA-2048 key pair, correlation-id, secret-key)
  - Per-test OOB hostname generation (``{corr_id}{nonce}.{domain}``)
  - Polling and AES-256-CFB decryption of server callbacks
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
import uuid
from typing import Optional
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class InteractshClient:
    """Minimal async client for a projectdiscovery interactsh-compatible server.

    Supports:
      - Registering with the server to obtain a ``correlation-id`` / ``secret-key``
      - Generating per-test OOB interaction URLs (``{corr_id}{nonce}.{domain}``)
      - Polling ``/poll`` for any logged interactions

    Falls back gracefully if the server is unreachable.
    """

    # Length of the random nonce appended after the correlation ID in each hostname.
    # Total first label = len(correlation_id) + NONCE_LENGTH = 20 + 13 = 33 chars.
    NONCE_LENGTH: int = 13

    def __init__(self, server_url: str) -> None:
        parsed = urlparse(server_url.rstrip("/"))
        self._api_base = f"{parsed.scheme}://{parsed.netloc}"
        self._interaction_domain = parsed.netloc  # e.g. oast.live
        self._http = httpx.AsyncClient(timeout=15, verify=False)
        self.correlation_id: Optional[str] = None
        self.secret_key: Optional[str] = None
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._registered: bool = False

    async def register(self) -> None:
        """Register with the interactsh server and store credentials.

        The server requires a JSON body with:
          - ``public-key``     RSA-2048 public key PEM, base64-encoded
          - ``secret-key``     UUID v4 string (matches the official client format)
          - ``correlation-id`` 20 random lowercase alphanumeric characters

        Poll responses use AES-256-CFB encryption; the AES key is RSA-OAEP
        encrypted with our public key and returned in the ``aes_key`` field.
        """
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            pub_pem = self._private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
            self.correlation_id = "".join(secrets.choice(alphabet) for _ in range(20))
            # Secret key must be a UUID string — this is what the official client sends
            self.secret_key = str(uuid.uuid4())

            payload = {
                "public-key": base64.b64encode(pub_pem).decode(),
                "secret-key": self.secret_key,
                "correlation-id": self.correlation_id,
            }
            resp = await self._http.post(
                f"{self._api_base}/register", json=payload
            )
            resp.raise_for_status()
            self._registered = True
            logger.info(
                "Interactsh registered — correlation-id=%s domain=%s",
                self.correlation_id,
                self._interaction_domain,
            )
        except Exception as exc:
            logger.warning(
                "Interactsh registration failed: %s — OOB detection disabled", exc
            )

    def interaction_host(self, test_id: str) -> str:
        """Return the unique OOB hostname for *test_id*.

        Correct format: ``{correlation_id}{test_id}.{domain}``

        The server identifies the client by reading the **first 20 chars** of
        the subdomain label as the correlation ID.  The remaining chars are a
        per-test nonce that comes back as ``unique-id`` in poll results.
        *test_id* must be at most :attr:`NONCE_LENGTH` (13) chars.
        """
        if not self._registered or not self.correlation_id:
            return ""
        # Pad/trim so the nonce portion is always NONCE_LENGTH chars
        nonce = test_id[:self.NONCE_LENGTH].ljust(self.NONCE_LENGTH, "0")
        return f"{self.correlation_id}{nonce}.{self._interaction_domain}"

    def interaction_test_id(self, test_id: str) -> str:
        """Return the nonce portion embedded in the hostname for *test_id*."""
        return test_id[:self.NONCE_LENGTH].ljust(self.NONCE_LENGTH, "0")

    async def poll(self) -> list[dict]:
        """Poll for interactions; return a list of decoded interaction dicts."""
        if not self._registered or not self._private_key:
            return []
        try:
            resp = await self._http.get(
                f"{self._api_base}/poll",
                params={
                    "id": self.correlation_id,
                    "secret": self.secret_key or "",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            encrypted_data: list[str] = list(data.get("data") or [])
            aes_key_b64: str = data.get("aes_key", "")
            if not encrypted_data or not aes_key_b64:
                return []

            # RSA-OAEP-SHA256 decrypt the AES key
            aes_key = self._private_key.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Each entry is base64(IV[16] + AES-256-CFB ciphertext)
            results: list[dict] = []
            block_size = algorithms.AES.block_size // 8  # 16
            for entry in encrypted_data:
                raw = base64.b64decode(entry)
                iv, ciphertext = raw[:block_size], raw[block_size:]
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                plaintext = cipher.decryptor().update(ciphertext)
                try:
                    results.append(json.loads(plaintext.rstrip(b"\n")))
                except Exception:
                    logger.debug("Failed to parse interaction JSON: %r", plaintext[:100])
            return results
        except Exception as exc:
            logger.debug("Interactsh poll error: %s", exc, exc_info=True)
            return []

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()
