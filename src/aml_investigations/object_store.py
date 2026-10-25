"""Object-store adapters for evidence blobs.

``S3ObjectStore`` talks to any S3-compatible endpoint (SeaweedFS in
docker-compose, service name ``minio``, path-style addressing). It
signs requests with AWS Signature Version 4 when credentials are
provided in the environment; against the compose SeaweedFS gateway,
which runs without auth, it sends unsigned requests.

``LocalObjectStore`` is the filesystem double used by local runs and
tests. Both honour the same contract: put/get only — evidence blobs
are never updated or deleted through this port (Law 5).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx


class LocalObjectStore:
    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def ping(self) -> bool:
        return self._root.is_dir()

    def _path(self, key: str) -> Path:
        path = (self._root / key).resolve()
        if not str(path).startswith(str(self._root.resolve())):
            raise ValueError(f"object key escapes the store root: {key}")
        return path

    def put(self, key: str, content: bytes, media_type: str) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-once posture: an existing blob is never overwritten.
        if path.exists():
            if path.read_bytes() != content:
                raise ValueError(f"object already exists with different content: {key}")
            return
        path.write_bytes(content)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


class S3ObjectStore:
    """Minimal S3-compatible client (path-style), SigV4 when keyed."""

    def __init__(
        self,
        endpoint_url: str,
        bucket: str,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str = "us-east-1",
        client: httpx.Client | None = None,
    ) -> None:
        self._endpoint = endpoint_url.rstrip("/")
        self._bucket = bucket
        self._access_key = access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self._secret_key = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self._region = region
        self._client = client or httpx.Client(timeout=30.0)
        self._bucket_ready = False

    def _url(self, key: str) -> str:
        return f"{self._endpoint}/{self._bucket}/{key}"

    def _headers(self, method: str, key: str, content: bytes) -> dict[str, str]:
        headers: dict[str, str] = {}
        if not (self._access_key and self._secret_key):
            return headers
        now = datetime.now(timezone.utc)
        datestamp = now.strftime("%Y%m%d")
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        payload_hash = hashlib.sha256(content).hexdigest()
        canonical_uri = f"/{self._bucket}/{key}"
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        host = self._endpoint.split("://", 1)[1]
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amzdate}\n"
        )
        canonical_request = "\n".join(
            [method, canonical_uri, "", canonical_headers, signed_headers, payload_hash]
        )
        scope = f"{datestamp}/{self._region}/s3/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amzdate,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        k_date = _sign(("AWS4" + self._secret_key).encode(), datestamp)
        k_region = _sign(k_date, self._region)
        k_service = _sign(k_region, "s3")
        k_signing = _sign(k_service, "aws4_request")
        signature = hmac.new(
            k_signing, string_to_sign.encode(), hashlib.sha256
        ).hexdigest()
        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self._access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers["x-amz-date"] = amzdate
        headers["x-amz-content-sha256"] = payload_hash
        return headers

    def _ensure_bucket(self) -> None:
        if self._bucket_ready:
            return
        # Plain unsigned PUT creates the bucket on SeaweedFS; on a
        # real S3 the bucket is provisioned out of band and this PUT
        # is a no-op error we can ignore if the bucket already exists.
        try:
            self._client.put(f"{self._endpoint}/{self._bucket}")
        except httpx.HTTPError:
            pass
        self._bucket_ready = True

    def ping(self) -> bool:
        try:
            response = self._client.get(f"{self._endpoint}/{self._bucket}")
            return response.status_code < 500
        except httpx.HTTPError:
            return False

    def put(self, key: str, content: bytes, media_type: str) -> None:
        self._ensure_bucket()
        headers = self._headers("PUT", key, content)
        headers["Content-Type"] = media_type
        response = self._client.put(self._url(key), content=content, headers=headers)
        response.raise_for_status()

    def get(self, key: str) -> bytes:
        headers = self._headers("GET", key, b"")
        response = self._client.get(self._url(key), headers=headers)
        response.raise_for_status()
        return response.content
