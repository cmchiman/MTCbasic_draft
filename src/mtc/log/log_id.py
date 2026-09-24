"""Log IDs and trust anchor IDs.

A log ID is a trust anchor ID that uniquely identifies an issuance log.  In the
TLS structures a trust anchor ID is carried as ``opaque TrustAnchorID<1..2^8-1>``,
i.e. an opaque byte string of at most 255 bytes, and a log ID additionally
determines an X.509 distinguished name.

Representation choice
---------------------
The value is carried as an opaque byte string, so the exact binary
representation is a deployment choice.  The default construction encodes the
arcs of the ID, and arbitrary byte strings are accepted when a deployment uses
a different encoding.

For the distinguished name, an experimental profile is used: the attribute type
is ``1.3.6.1.4.1.44363.47.1`` and the value is a ``UTF8String`` holding the
trust anchor ID's ASCII representation (e.g. ``32473.1``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Union

from ..common.errors import DecodeError, EncodingError
from ..encoding.der import decode_arcs, decode_oid, encode_arcs, encode_oid

#: Attribute type OID used by early implementations.
EXPERIMENTAL_RDNA_TRUST_ANCHOR_ID_OID = "1.3.6.1.4.1.44363.47.1"

#: The final (not yet assigned) attribute type OID, ``id-rdna-trustAnchorID``.
RDNA_TRUST_ANCHOR_ID_OID = "1.3.6.1.5.5.7.25.TBD"

MAX_TRUST_ANCHOR_ID_LENGTH = 255


@dataclass(frozen=True)
class TrustAnchorID:
    """A trust anchor ID in its binary representation."""

    binary: bytes

    def __post_init__(self) -> None:
        data = bytes(self.binary)
        if not data:
            raise EncodingError("a trust anchor ID must not be empty")
        if len(data) > MAX_TRUST_ANCHOR_ID_LENGTH:
            raise EncodingError(
                f"a trust anchor ID must be at most {MAX_TRUST_ANCHOR_ID_LENGTH} bytes"
            )
        object.__setattr__(self, "binary", data)

    # -- constructors -----------------------------------------------------
    @classmethod
    def from_arcs(cls, arcs: Union[str, Sequence[int]]) -> "TrustAnchorID":
        """Build a trust anchor ID from OID arcs, e.g. ``"32473.1"``.

        The binary representation used by default is the sequence of base-128
        encoded arcs, so the log named 32473.1 is encoded as ``81fd5901``.
        """
        return cls(encode_arcs(arcs))

    @classmethod
    def from_oid_der(cls, arcs: Union[str, Sequence[int]]) -> "TrustAnchorID":
        """Build a trust anchor ID whose binary form is a DER ``OBJECT IDENTIFIER``."""
        return cls(encode_oid(arcs))

    @classmethod
    def from_opaque(cls, data: bytes) -> "TrustAnchorID":
        """Build a trust anchor ID from an opaque binary representation."""
        return cls(bytes(data))

    # -- accessors --------------------------------------------------------
    @property
    def arcs(self) -> str:
        """The dotted OID text, when the binary form is a DER OID."""
        return self.to_arcs()

    def to_arcs(self) -> str:
        if self.binary and self.binary[0] == 0x06 and len(self.binary) >= 2:
            try:
                from ..encoding.der import read_tlv

                outer = read_tlv(self.binary, 0)
            except DecodeError:
                outer = None
            if outer is not None and outer.tag == 0x06 and outer.end == len(self.binary):
                return decode_oid(outer.content)
        return decode_arcs(self.binary)

    def ascii_representation(self) -> str:
        """The ASCII representation used by the experimental DN profile."""
        try:
            return self.to_arcs()
        except DecodeError:
            return self.binary.decode("ascii", errors="replace")

    def relative_distinguished_name(self, oid: str = EXPERIMENTAL_RDNA_TRUST_ANCHOR_ID_OID):
        """The single-attribute RDN that names this log.

        The returned object is the :class:`~mtc.x509.RelativeDistinguishedName`
        that the log ID must appear as inside every ``TBSCertificateLogEntry``
        and every Merkle Tree certificate.
        """
        from ..encoding.asn1 import AttributeTypeAndValue, RelativeDistinguishedName

        return RelativeDistinguishedName(
            (AttributeTypeAndValue.utf8_string(oid, self.ascii_representation()),)
        )

    def distinguished_name(self, oid: str = EXPERIMENTAL_RDNA_TRUST_ANCHOR_ID_OID):
        """The log ID's X.509 ``Name``.

        The distinguished name has a single relative distinguished name with a
        single attribute.
        """
        from ..encoding.asn1 import Name

        return Name((self.relative_distinguished_name(oid),))

    # -- dunder -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self.binary)

    def __bytes__(self) -> bytes:
        return self.binary

    def __repr__(self) -> str:
        try:
            text = self.to_arcs()
        except DecodeError:
            text = self.binary.hex()
        return f"TrustAnchorID({text!r})"


def trust_anchor_id_from_oid(arcs: Union[str, Sequence[int]]) -> TrustAnchorID:
    """Convenience wrapper around :meth:`TrustAnchorID.from_arcs`."""
    return TrustAnchorID.from_arcs(arcs)


#: A log ID *is* a trust anchor ID.  Both names denote the same class, so
#: ``LogID(...)`` and ``TrustAnchorID(...)`` are interchangeable.
LogID = TrustAnchorID
