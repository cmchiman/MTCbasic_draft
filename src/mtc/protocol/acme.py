"""ACME certificate-download semantics for draft-10 section 9.

The response body contains real PEM-encoded certificate DER.  Trust Anchor
properties remain semantic objects until the external wire format is fixed.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Mapping, Optional

from ..core.errors import EncodingError
from ..log.log_id import TrustAnchorID
from ..service.real_certificate import RealCertificateArtifact
from .certificate_selector import LandmarkCompatibilityRange


MTC_CERTIFICATE_CHAIN_MEDIA_TYPE = (
    "application/pem-certificate-chain-with-properties"
)


def _pem_certificate(certificate_der: bytes) -> bytes:
    encoded = base64.b64encode(certificate_der)
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"\n".join(lines)
        + b"\n-----END CERTIFICATE-----\n"
    )


@dataclass(frozen=True)
class AcmeCertificateProperties:
    """Semantic CertificatePropertyList information, not its wire codec."""

    certificate_kind: str
    routing_trust_anchor_id: TrustAnchorID
    verification_log_id: TrustAnchorID
    landmark_range: Optional[LandmarkCompatibilityRange] = None

    def __post_init__(self) -> None:
        if self.certificate_kind not in ("full", "signatureless"):
            raise EncodingError("unsupported ACME certificate kind")
        if not isinstance(self.routing_trust_anchor_id, TrustAnchorID):
            raise EncodingError("ACME routing ID must be a TrustAnchorID")
        if not isinstance(self.verification_log_id, TrustAnchorID):
            raise EncodingError("ACME verification ID must be a TrustAnchorID")
        if self.certificate_kind == "full":
            if self.routing_trust_anchor_id != self.verification_log_id:
                raise EncodingError("Full ACME property must route by log ID")
            if self.landmark_range is not None:
                raise EncodingError("Full ACME property cannot carry Landmark range")
        elif not isinstance(self.landmark_range, LandmarkCompatibilityRange):
            raise EncodingError("Signatureless ACME property needs Landmark range")

    @classmethod
    def from_artifact(
        cls, artifact: RealCertificateArtifact
    ) -> "AcmeCertificateProperties":
        if not isinstance(artifact, RealCertificateArtifact):
            raise EncodingError("ACME requires a real opaque DER artifact")
        compatibility = None
        if artifact.certificate_kind == "signatureless":
            assert artifact.landmark_base_id is not None
            assert artifact.landmark_number is not None
            assert artifact.landmark_max_landmarks is not None
            compatibility = LandmarkCompatibilityRange(
                verification_log_id=artifact.verification_log_id,
                base_id=artifact.landmark_base_id,
                minimum=artifact.landmark_number,
                maximum=(
                    artifact.landmark_number
                    + artifact.landmark_max_landmarks
                    - 1
                ),
            )
        return cls(
            artifact.certificate_kind,
            artifact.routing_trust_anchor_id,
            artifact.verification_log_id,
            compatibility,
        )


@dataclass(frozen=True)
class AcmeCertificateResource:
    url: str
    certificate: Optional[RealCertificateArtifact]
    chain_der: tuple[bytes, ...] = ()
    alternate_url: Optional[str] = None
    retry_after_seconds: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url:
            raise EncodingError("ACME resource URL must be non-empty")
        if self.certificate is not None and not isinstance(
            self.certificate, RealCertificateArtifact
        ):
            raise EncodingError("ACME certificate must be a real DER artifact")
        chain = tuple(bytes(item) for item in self.chain_der)
        if any(not item for item in chain):
            raise EncodingError("ACME chain DER entries must be non-empty")
        object.__setattr__(self, "chain_der", chain)
        if self.alternate_url is not None and (
            not isinstance(self.alternate_url, str) or not self.alternate_url
        ):
            raise EncodingError("alternate URL must be non-empty text")
        if self.certificate is None:
            if (
                isinstance(self.retry_after_seconds, bool)
                or not isinstance(self.retry_after_seconds, int)
                or self.retry_after_seconds < 0
            ):
                raise EncodingError("pending ACME resource needs Retry-After")
        elif self.retry_after_seconds is not None:
            raise EncodingError("available ACME resource cannot be pending")


@dataclass(frozen=True)
class AcmeDownloadResponse:
    status_code: int
    content_type: Optional[str] = None
    body: bytes = b""
    certificate_chain_der: tuple[bytes, ...] = ()
    properties: Optional[AcmeCertificateProperties] = None
    alternate_url: Optional[str] = None
    retry_after_seconds: Optional[int] = None

    @property
    def network_bytes(self) -> int:
        """Known serialized response bytes; semantic properties are excluded."""
        headers = []
        if self.content_type is not None:
            headers.append(f"Content-Type: {self.content_type}\r\n".encode("ascii"))
        if self.alternate_url is not None:
            headers.append(f"Link: <{self.alternate_url}>;rel=alternate\r\n".encode("utf-8"))
        if self.retry_after_seconds is not None:
            headers.append(f"Retry-After: {self.retry_after_seconds}\r\n".encode("ascii"))
        status = f"Status: {self.status_code}\r\n".encode("ascii")
        return len(status) + sum(map(len, headers)) + 2 + len(self.body)


class AcmeSemanticService:
    def __init__(self, resources: Mapping[str, AcmeCertificateResource]) -> None:
        values = dict(resources)
        if any(url != resource.url for url, resource in values.items()):
            raise EncodingError("ACME resource map key and URL differ")
        self._resources = values

    def download(self, url: str, *, accept: str) -> AcmeDownloadResponse:
        if accept != MTC_CERTIFICATE_CHAIN_MEDIA_TYPE:
            return AcmeDownloadResponse(status_code=406)
        resource = self._resources.get(url)
        if resource is None:
            return AcmeDownloadResponse(status_code=404)
        if resource.certificate is None:
            return AcmeDownloadResponse(
                status_code=503,
                retry_after_seconds=resource.retry_after_seconds,
            )
        chain = (resource.certificate.certificate_der,) + resource.chain_der
        body = b"".join(_pem_certificate(item) for item in chain)
        return AcmeDownloadResponse(
            status_code=200,
            content_type=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
            body=body,
            certificate_chain_der=chain,
            properties=AcmeCertificateProperties.from_artifact(
                resource.certificate
            ),
            alternate_url=resource.alternate_url,
        )


class AcmeSemanticClient:
    """Validate the semantic response without inventing properties wire bytes."""

    def accepts(
        self,
        response: object,
        *,
        expected_properties: AcmeCertificateProperties,
    ) -> bool:
        if (
            not isinstance(response, AcmeDownloadResponse)
            or not isinstance(expected_properties, AcmeCertificateProperties)
            or response.status_code != 200
            or response.content_type != MTC_CERTIFICATE_CHAIN_MEDIA_TYPE
            or not response.certificate_chain_der
            or not response.body
            or response.properties != expected_properties
        ):
            return False
        expected_body = b"".join(
            _pem_certificate(item) for item in response.certificate_chain_der
        )
        return response.body == expected_body


__all__ = [
    "MTC_CERTIFICATE_CHAIN_MEDIA_TYPE",
    "AcmeCertificateProperties",
    "AcmeCertificateResource",
    "AcmeDownloadResponse",
    "AcmeSemanticClient",
    "AcmeSemanticService",
]
