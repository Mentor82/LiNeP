from __future__ import annotations

from linep_sl._cabi_sl import ffi, lib


class PeerIdentity:
    __slots__ = ("trust_domain_id", "node_id", "pubkey", "revoked")

    def __init__(
        self,
        trust_domain_id: int,
        node_id: int,
        pubkey: bytes,
        revoked: bool = False,
    ) -> None:
        self.trust_domain_id = trust_domain_id
        self.node_id = node_id
        self.pubkey = pubkey
        self.revoked = revoked


class SessionKey:
    __slots__ = ("session_id", "key_id", "established_at_sec", "expires_at_sec", "secret_key")

    def __init__(
        self,
        session_id: int,
        key_id: int,
        established_at_sec: int,
        expires_at_sec: int,
        secret_key: bytes,
    ) -> None:
        self.session_id = session_id
        self.key_id = key_id
        self.established_at_sec = established_at_sec
        self.expires_at_sec = expires_at_sec
        self.secret_key = secret_key


def validate_peer_identity(peer: PeerIdentity, expected_trust_domain: int) -> bool:
    if len(peer.pubkey) != 32:
        return False

    peer_struct = ffi.new("linep_sl2_peer_identity_t *")
    peer_struct.trust_domain_id = peer.trust_domain_id
    peer_struct.node_id = peer.node_id
    ffi.memmove(peer_struct.pubkey, peer.pubkey, 32)
    peer_struct.revoked = 1 if peer.revoked else 0

    rc = lib.linep_sl2_validate_peer_identity(peer_struct, expected_trust_domain)
    return rc == 1


def derive_session_key(
    master_secret: bytes,
    session_id: int,
    key_id: int,
    node_id: int,
    ttl_sec: int,
    current_time_sec: int,
) -> SessionKey:
    c_secret = ffi.from_buffer(bytes(master_secret))
    sk_struct = ffi.new("linep_sl2_session_key_t *")

    rc = lib.linep_sl2_derive_session_key(
        c_secret,
        len(master_secret),
        session_id,
        key_id,
        node_id,
        ttl_sec,
        current_time_sec,
        sk_struct,
    )
    if rc != 1:
        raise RuntimeError("linep_sl2_derive_session_key failed")

    secret_key = bytes(ffi.buffer(sk_struct.secret_key, 32))
    return SessionKey(
        session_id=sk_struct.session_id,
        key_id=sk_struct.key_id,
        established_at_sec=sk_struct.established_at_sec,
        expires_at_sec=sk_struct.expires_at_sec,
        secret_key=secret_key,
    )


def verify_session_key_freshness(key: SessionKey, current_time_sec: int) -> bool:
    if len(key.secret_key) != 32:
        return False

    sk_struct = ffi.new("linep_sl2_session_key_t *")
    sk_struct.session_id = key.session_id
    sk_struct.key_id = key.key_id
    sk_struct.established_at_sec = key.established_at_sec
    sk_struct.expires_at_sec = key.expires_at_sec
    ffi.memmove(sk_struct.secret_key, key.secret_key, 32)

    rc = lib.linep_sl2_verify_session_key_freshness(sk_struct, current_time_sec)
    return rc == 1
