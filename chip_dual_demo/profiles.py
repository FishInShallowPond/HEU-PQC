"""LC01 macro commands and actual wire widths from the existing algorithm tester.

Widths are transport widths, never padded to the nominal algorithm sizes.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    key: str
    name: str
    family: str
    config_hex: str
    pk_bytes: int
    sk_bytes: int
    ct_bytes: int = 0
    k_bytes: int = 0
    signature_bytes: int = 0


def _kem(key, name, command):
    return Profile(key, name, 'kem', command, 800, 1632, 768, 32)


def _sig(key, name, command, pk, sk, signature):
    return Profile(key, name, 'signature', command, pk, sk, signature_bytes=signature)


PROFILES = {p.key: p for p in (
    _kem('kyber512', 'Kyber512', '020001000011'),
    _kem('kyber768', 'Kyber768', '020001000012'),
    _kem('kyber1024', 'Kyber1024', '020001000013'),
    _kem('aigis-enc1', 'Aigis-ENC I', '020001000051'),
    _kem('aigis-enc2', 'Aigis-ENC II', '020001000052'),
    _kem('aigis-enc3', 'Aigis-ENC III', '020001000053'),
    _sig('dilithium2', 'Dilithium 2', '020001000071', 1312, 2528, 2420),
    _sig('dilithium3', 'Dilithium 3', '020001000072', 1952, 4000, 3293),
    _sig('dilithium5', 'Dilithium 5', '020001000073', 2592, 4864, 4595),
    _sig('aigis-sig1', 'Aigis-SIG I', '020001000091', 1312, 2528, 2420),
    _sig('aigis-sig2', 'Aigis-SIG II', '020001000092', 1952, 4000, 3293),
    _sig('aigis-sig2b', 'Aigis-SIG II-B', '020001000093', 1952, 4000, 3293),
    _sig('aigis-sig3', 'Aigis-SIG III', '020001000094', 2592, 4864, 4595),
)}
