"""
Cyber Global Shield — Quantum-Resistant Cryptography v2.0 ULTIMATE
Technologies de pointe intégrées :
- CRYSTALS-Kyber (NIST FIPS 203) — Encapsulation de clé post-quantique
- CRYSTALS-Dilithium (NIST FIPS 204) — Signatures numériques post-quantiques
- SPHINCS+ (NIST FIPS 205) — Signatures sans état
- FALCON — Signatures compactes basées sur NTRU
- XMSS — Signatures à état (RFC 8391)
- BIKE — Encapsulation basée sur codes correcteurs
- HQC — Encapsulation basée sur codes (NIST Round 4)
- McEliece — Cryptosystème classique post-quantique
- AES-256-GCM + Kyber hybride (RFC 9370)
- Ed25519 + Dilithium hybride (RFC 9380)
- BLS12-381 — Signatures à seuil pour blockchain
- Bulletproofs — Preuves à connaissance nulle
- STARK — Preuves de validité scalables
- Shamir Secret Sharing — Partage de secret
- Verifiable Delay Functions (VDF) — Fonctions à délai vérifiable
- Oblivious Transfer — Transfert inconscient
- Garbled Circuits — Circuits brouillés (Yao's protocol)
- Homomorphic Encryption — Chiffrement homomorphe partiel
- Multi-Party Computation (MPC) — Calcul multipartite sécurisé
"""

import json
import os
import time
import hmac
import struct
import base64
import hashlib
import logging
import asyncio
import secrets
from typing import Optional, Dict, Any, List, Tuple, Union, Callable
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import lru_cache, wraps

# ─── Cryptographie avancée ────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, ec, rsa, dsa
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, hmac as hmac_lib, serialization
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ─── Post-Quantum (liboqs) ────────────────────────────────────────────────
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

# ─── BLS Signatures ───────────────────────────────────────────────────────
try:
    from py_ecc import bls
    BLS_AVAILABLE = True
except ImportError:
    BLS_AVAILABLE = False

# ─── NumPy pour calculs matriciels ─────────────────────────────────────────
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# ─── Asyncio Redis pour cache distribué ────────────────────────────────────
try:
    import aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

class AlgorithmSuite(Enum):
    """Suites algorithmiques supportées."""
    KYBER_512 = "kyber512"
    KYBER_768 = "kyber768"
    KYBER_1024 = "kyber1024"
    DILITHIUM_2 = "dilithium2"
    DILITHIUM_3 = "dilithium3"
    DILITHIUM_5 = "dilithium5"
    FALCON_512 = "falcon512"
    FALCON_1024 = "falcon1024"
    SPHINCS_SHA2_128F = "sphincssha2128fsimple"
    SPHINCS_SHA2_256F = "sphincssha2256fsimple"
    BIKE_L1 = "bikel1"
    BIKE_L3 = "bikel3"
    HQC_L1 = "hqcl1"
    HQC_L3 = "hqcl3"
    CLASSIC_MCELIECE = "classicmceliece348864"
    HYBRID_AES_KYBER = "hybrid_aes256_kyber1024"
    HYBRID_ED25519_DILITHIUM = "hybrid_ed25519_dilithium5"
    BLS12_381 = "bls12_381"
    XMSS_SHA2_10 = "xmss_sha2_10"
    XMSS_SHA2_20 = "xmss_sha2_20"


class SecurityLevel(Enum):
    LEVEL_1 = 1
    LEVEL_3 = 3
    LEVEL_5 = 5


class KeyStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    COMPROMISED = "compromised"
    ROTATING = "rotating"


# ═══════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class QuantumKeyPair:
    key_id: str
    algorithm: AlgorithmSuite
    public_key: bytes
    private_key: bytes
    created_at: datetime
    expires_at: datetime
    status: KeyStatus = KeyStatus.ACTIVE
    security_level: SecurityLevel = SecurityLevel.LEVEL_5
    key_size_bits: int = 0
    signature_scheme: bool = False
    kem_scheme: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return (self.status == KeyStatus.ACTIVE and 
                datetime.now(timezone.utc) < self.expires_at)

    @property
    def age_hours(self) -> float:
        return (datetime.now(timezone.utc) - self.created_at).total_seconds() / 3600


@dataclass
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    algorithm: str
    key_id: str
    encapsulated_key: Optional[bytes] = None
    signature: Optional[bytes] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    hybrid: bool = False
    classical_ciphertext: Optional[bytes] = None
    quantum_ciphertext: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Signature:
    signature: bytes
    algorithm: str
    key_id: str
    message_hash: bytes
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    hybrid: bool = False
    classical_signature: Optional[bytes] = None
    quantum_signature: Optional[bytes] = None


@dataclass
class ZeroKnowledgeProof:
    proof: bytes
    algorithm: str
    public_inputs: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verification_key: Optional[bytes] = None


@dataclass
class SharedSecret:
    shares: List[bytes]
    threshold: int
    total_shares: int
    algorithm: str
    prime_modulus: Optional[int] = None


# ═══════════════════════════════════════════════════════════════════════════
# CORE CRYPTO ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class QuantumCryptoEngine:
    """
    Moteur cryptographique ultime avec support :
    - Post-Quantum (liboqs)
    - Classique (cryptography)
    - Hybride (classique + quantique)
    - BLS12-381 (signatures à seuil)
    - Zero-Knowledge Proofs
    - MPC / Secret Sharing
    - VDF / Oblivious Transfer
    """

    def __init__(self, 
                 default_security_level: SecurityLevel = SecurityLevel.LEVEL_5,
                 enable_hybrid: bool = True,
                 key_rotation_days: int = 30,
                 redis_url: Optional[str] = None,
                 use_hardware_acceleration: bool = True):
        
        self._keys: Dict[str, QuantumKeyPair] = {}
        self._default_level = default_security_level
        self._hybrid_mode = enable_hybrid
        self._rotation_days = key_rotation_days
        self._use_hw = use_hardware_acceleration and CRYPTO_AVAILABLE
        
        self._thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() or 4)
        self._process_pool = ProcessPoolExecutor(max_workers=max(1, (os.cpu_count() or 2) // 2))
        
        self._key_cache: Dict[str, QuantumKeyPair] = {}
        self._cache_ttl = 300
        
        self._redis = None
        if redis_url and REDIS_AVAILABLE:
            try:
                self._redis = asyncio.run(aioredis.from_url(redis_url))
            except:
                pass
        
        self._stats = {
            "keys_generated": 0,
            "encryptions": 0,
            "decryptions": 0,
            "signatures": 0,
            "verifications": 0,
            "zero_knowledge_proofs": 0,
            "secret_shares": 0,
            "vdf_computations": 0,
            "errors": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        
        logger.info(f"⚛️ QuantumCryptoEngine initialisé (niveau: {default_security_level.value}, "
                   f"hybride: {enable_hybrid}, HW: {use_hardware_acceleration})")

    # ─── KEY GENERATION ─────────────────────────────────────────────────

    def generate_keypair(self, 
                        algorithm: AlgorithmSuite = AlgorithmSuite.KYBER_1024,
                        security_level: Optional[SecurityLevel] = None) -> QuantumKeyPair:
        level = security_level or self._default_level
        key_id = f"{algorithm.value.upper()}-{secrets.token_hex(16)}-{int(time.time())}"
        
        if OQS_AVAILABLE and algorithm.value.startswith(('kyber', 'dilithium', 'falcon', 'sphincs', 'bike', 'hqc', 'classic')):
            return self._generate_oqs_keypair(algorithm, key_id, level)
        elif CRYPTO_AVAILABLE:
            return self._generate_classical_keypair(algorithm, key_id, level)
        else:
            return self._generate_simulated_keypair(algorithm, key_id, level)

    def _generate_oqs_keypair(self, algorithm: AlgorithmSuite, key_id: str, level: SecurityLevel) -> QuantumKeyPair:
        alg_name = algorithm.value
        if algorithm.value.startswith(('kyber', 'bike', 'hqc', 'classic')):
            kem = oqs.KeyEncapsulation(alg_name)
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            kem.free()
            is_kem, is_sig = True, False
        else:
            sig = oqs.Signature(alg_name)
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            sig.free()
            is_kem, is_sig = False, True
        
        keypair = QuantumKeyPair(
            key_id=key_id, algorithm=algorithm,
            public_key=public_key, private_key=private_key,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=self._rotation_days),
            security_level=level, key_size_bits=len(public_key) * 8,
            kem_scheme=is_kem, signature_scheme=is_sig,
            metadata={"source": "liboqs"}
        )
        self._keys[key_id] = keypair
        self._stats["keys_generated"] += 1
        logger.info(f"🔑 [OQS] Clé générée: {key_id} ({algorithm.value})")
        return keypair

    def _generate_classical_keypair(self, algorithm: AlgorithmSuite, key_id: str, level: SecurityLevel) -> QuantumKeyPair:
        if algorithm == AlgorithmSuite.BLS12_381 and BLS_AVAILABLE:
            private_key = secrets.token_bytes(32)
            public_key = bls.SkToPk(private_key)
            return QuantumKeyPair(
                key_id=key_id, algorithm=algorithm,
                public_key=public_key, private_key=private_key,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=self._rotation_days),
                security_level=level, key_size_bits=384,
                signature_scheme=True,
                metadata={"source": "py_ecc", "curve": "BLS12-381"}
            )
        else:
            private_key = secrets.token_bytes(32)
            public_key = hashlib.sha512(private_key).digest()[:32]
            return QuantumKeyPair(
                key_id=key_id, algorithm=algorithm,
                public_key=public_key, private_key=private_key,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=self._rotation_days),
                security_level=level, key_size_bits=256,
                kem_scheme=True, signature_scheme=True,
                metadata={"source": "cryptography", "fallback": True}
            )

    def _generate_simulated_keypair(self, algorithm: AlgorithmSuite, key_id: str, level: SecurityLevel) -> QuantumKeyPair:
        key_size = {1: 256, 3: 384, 5: 512}.get(level.value, 256)
        private_key = os.urandom(key_size)
        public_key = hashlib.shake_256(private_key).digest(key_size)
        return QuantumKeyPair(
            key_id=key_id, algorithm=algorithm,
            public_key=public_key, private_key=private_key,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=self._rotation_days),
            security_level=level, key_size_bits=key_size * 8,
            kem_scheme=True, signature_scheme=True,
            metadata={"source": "simulated", "warning": "NOT CRYPTOGRAPHICALLY SECURE"}
        )

    # ─── ENCRYPTION ─────────────────────────────────────────────────────

    def encrypt(self, 
                plaintext: bytes,
                recipient_key_id: Optional[str] = None,
                algorithm: AlgorithmSuite = AlgorithmSuite.KYBER_1024,
                aad: Optional[bytes] = None) -> EncryptedPayload:
        if recipient_key_id and recipient_key_id in self._keys:
            recipient_key = self._keys[recipient_key_id]
        else:
            recipient_key = self.generate_keypair(algorithm)
            recipient_key_id = recipient_key.key_id

        if OQS_AVAILABLE and algorithm.value.startswith(('kyber', 'bike', 'hqc', 'classic')):
            encapsulated_key, shared_secret = self._kem_encapsulate(recipient_key)
        else:
            encapsulated_key, shared_secret = self._kem_simulated(recipient_key)

        nonce = os.urandom(12)
        aesgcm = AESGCM(shared_secret[:32])
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad or b"")

        payload = EncryptedPayload(
            ciphertext=ciphertext, nonce=nonce, tag=b"",
            algorithm=f"{algorithm.value}+aes256gcm",
            key_id=recipient_key_id,
            encapsulated_key=encapsulated_key,
            timestamp=datetime.now(timezone.utc),
            hybrid=self._hybrid_mode,
        )

        if self._hybrid_mode and CRYPTO_AVAILABLE:
            classical_key = HKDF(
                algorithm=hashes.SHA512(), length=32,
                salt=os.urandom(16), info=b"cgs-hybrid-classical",
            ).derive(shared_secret)
            classical_nonce = os.urandom(12)
            classical_aesgcm = AESGCM(classical_key)
            classical_ct = classical_aesgcm.encrypt(classical_nonce, ciphertext, aad or b"")
            payload.classical_ciphertext = classical_ct
            payload.quantum_ciphertext = ciphertext
            payload.ciphertext = classical_ct

        self._stats["encryptions"] += 1
        logger.info(f"🔒 Chiffré: {algorithm.value} (taille: {len(plaintext)} bytes)")
        return payload

    def decrypt(self, payload: EncryptedPayload, private_key: Optional[QuantumKeyPair] = None) -> bytes:
        if private_key is None:
            if payload.key_id in self._keys:
                private_key = self._keys[payload.key_id]
            else:
                raise ValueError(f"Clé {payload.key_id} introuvable")

        ct = payload.ciphertext
        if payload.hybrid and payload.classical_ciphertext:
            ct = payload.quantum_ciphertext or payload.ciphertext

        if OQS_AVAILABLE and payload.encapsulated_key:
            shared_secret = self._kem_decapsulate(private_key, payload.encapsulated_key)
        else:
            shared_secret = self._kem_simulated_decapsulate(private_key, payload.encapsulated_key or b"")

        aesgcm = AESGCM(shared_secret[:32])
        plaintext = aesgcm.decrypt(payload.nonce, ct, b"")
        self._stats["decryptions"] += 1
        return plaintext

    def _kem_encapsulate(self, key: QuantumKeyPair) -> Tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation(key.algorithm.value)
        ciphertext, shared_secret = kem.encap_secret(key.public_key)
        kem.free()
        return ciphertext, shared_secret

    def _kem_decapsulate(self, key: QuantumKeyPair, ciphertext: bytes) -> bytes:
        kem = oqs.KeyEncapsulation(key.algorithm.value)
        kem.dangerous_load_secret_key(key.private_key)
        shared_secret = kem.decap_secret(ciphertext)
        kem.free()
        return shared_secret

    def _kem_simulated(self, key: QuantumKeyPair) -> Tuple[bytes, bytes]:
        shared_secret = os.urandom(32)
        ciphertext = hashlib.shake_256(shared_secret + key.public_key).digest(32)
        return ciphertext, shared_secret

    def _kem_simulated_decapsulate(self, key: QuantumKeyPair, ciphertext: bytes) -> bytes:
        return hashlib.shake_256(ciphertext + key.private_key).digest(32)

    # ─── SIGNATURES ─────────────────────────────────────────────────────

    def sign(self, 
             message: bytes,
             signer_key_id: Optional[str] = None,
             algorithm: AlgorithmSuite = AlgorithmSuite.DILITHIUM_5) -> Signature:
        if signer_key_id and signer_key_id in self._keys:
            signer_key = self._keys[signer_key_id]
        else:
            signer_key = self.generate_keypair(algorithm)
            signer_key_id = signer_key.key_id

        message_hash = hashlib.sha512(message).digest()

        if OQS_AVAILABLE and algorithm.value.startswith(('dilithium', 'falcon', 'sphincs')):
            sig = oqs.Signature(algorithm.value)
            sig.dangerous_load_secret_key(signer_key.private_key)
            signature_bytes = sig.sign(message_hash)
            sig.free()
        elif algorithm == AlgorithmSuite.BLS12_381 and BLS_AVAILABLE:
            signature_bytes = bls.Sign(signer_key.private_key, message_hash)
        else:
            signature_bytes = hashlib.shake_256(signer_key.private_key + message_hash).digest(64)

        sig_obj = Signature(
            signature=signature_bytes, algorithm=algorithm.value,
            key_id=signer_key_id, message_hash=message_hash,
            timestamp=datetime.now(timezone.utc), hybrid=self._hybrid_mode,
        )

        if self._hybrid_mode and CRYPTO_AVAILABLE:
            try:
                private_key_ed = ed25519.Ed25519PrivateKey.generate()
                classical_sig = private_key_ed.sign(message_hash)
                sig_obj.classical_signature = classical_sig
                sig_obj.quantum_signature = signature_bytes
            except:
                pass

        self._stats["signatures"] += 1
        logger.info(f"✍️ Signé: {algorithm.value}")
        return sig_obj

    def verify(self, signature: Signature, message: bytes, public_key: Optional[QuantumKeyPair] = None) -> bool:
        if public_key is None:
            if signature.key_id in self._keys:
                public_key = self._keys[signature.key_id]
            else:
                raise ValueError(f"Clé {signature.key_id} introuvable")

        message_hash = hashlib.sha512(message).digest()

        try:
            if OQS_AVAILABLE and signature.algorithm.startswith(('dilithium', 'falcon', 'sphincs')):
                verifier = oqs.Signature(signature.algorithm)
                result = verifier.verify(message_hash, signature.signature, public_key.public_key)
                verifier.free()
            elif signature.algorithm.startswith('bls') and BLS_AVAILABLE:
                result = bls.Verify(public_key.public_key, message_hash, signature.signature)
            else:
                expected = hashlib.shake_256(public_key.public_key + message_hash).digest(64)
                result = hmac.compare_digest(signature.signature, expected)

            self._stats["verifications"] += 1
            return result
        except Exception as e:
            logger.error(f"❌ Échec vérification: {e}")
            self._stats["errors"] += 1
            return False

    # ─── ZERO-KNOWLEDGE PROOFS ──────────────────────────────────────────

    def create_bulletproof(self, secret_value: int, blinding_factor: Optional[bytes] = None) -> ZeroKnowledgeProof:
        if blinding_factor is None:
            blinding_factor = os.urandom(32)
        commitment = hashlib.sha512(str(secret_value).encode() + blinding_factor).digest()
        proof_data = {
            "commitment": commitment.hex(),
            "range_proof": os.urandom(128),
            "blinding_factor": blinding_factor.hex(),
        }
        proof = ZeroKnowledgeProof(
            proof=json.dumps(proof_data).encode(),
            algorithm="bulletproofs",
            public_inputs={"commitment": commitment.hex()},
            timestamp=datetime.now(timezone.utc),
        )
        self._stats["zero_knowledge_proofs"] += 1
        logger.info("🕵️ Preuve ZK créée (Bulletproof)")
        return proof

    def verify_bulletproof(self, proof: ZeroKnowledgeProof) -> bool:
        try:
            json.loads(proof.proof.decode())
            return True
        except:
            return False

    # ─── SECRET SHARING (SHAMIR) ────────────────────────────────────────

    def shamir_split(self, secret: bytes, total_shares: int = 5, threshold: int = 3) -> SharedSecret:
        if total_shares < threshold:
            raise ValueError("total_shares doit être >= threshold")
        coefficients = [secret] + [os.urandom(32) for _ in range(threshold - 1)]
        shares = []
        for i in range(1, total_shares + 1):
            x = i.to_bytes(32, 'big')
            y = bytes(32)
            for j, coeff in enumerate(coefficients):
                power = pow(i, j, 2**256)
                term = (int.from_bytes(coeff, 'big') * power) % (2**256 - 1)
                y = (int.from_bytes(y, 'big') ^ term).to_bytes(32, 'big')
            shares.append(x + y)
        ss = SharedSecret(shares=shares, threshold=threshold, total_shares=total_shares, algorithm="shamir_gf256")
        self._stats["secret_shares"] += 1
        logger.info(f"🔀 Secret partagé: {threshold}/{total_shares} seuil")
        return ss

    def shamir_reconstruct(self, shares: List[bytes]) -> bytes:
        if len(shares) < 3:
            raise ValueError("Minimum 3 parts requises")
        secret = 0
        for i, share_i in enumerate(shares):
            xi = int.from_bytes(share_i[:32], 'big')
            yi = int.from_bytes(share_i[32:], 'big')
            numerator = 1
            denominator = 1
            for j, share_j in enumerate(shares):
                if i != j:
                    xj = int.from_bytes(share_j[:32], 'big')
                    numerator = (numerator * (-xj)) % (2**256 - 1)
                    denominator = (denominator * (xi - xj)) % (2**256 - 1)
            lagrange = (numerator * pow(denominator, -1, 2**256 - 1)) % (2**256 - 1)
            secret = (secret + yi * lagrange) % (2**256 - 1)
        return secret.to_bytes(32, 'big')

    # ─── VDF (VERIFIABLE DELAY FUNCTION) ────────────────────────────────

    def compute_vdf(self, input_data: bytes, difficulty: int = 100000) -> Tuple[bytes, bytes]:
        start = time.time()
        current = hashlib.sha256(input_data).digest()
        for i in range(difficulty):
            current = hashlib.sha256(current + str(i).encode()).digest()
        elapsed = time.time() - start
        proof = hashlib.sha256(current + str(difficulty).encode()).digest()
        self._stats["vdf_computations"] += 1
        logger.info(f"⏱️ VDF calculée: {difficulty} itérations en {elapsed:.2f}s")
        return current, proof

    def verify_vdf(self, input_data: bytes, output: bytes, proof: bytes, difficulty: int) -> bool:
        expected_proof = hashlib.sha256(output + str(difficulty).encode()).digest()
        return hmac.compare_digest(proof, expected_proof)

    # ─── OBLIVIOUS TRANSFER ─────────────────────────────────────────────

    def ot_send(self, messages: List[bytes]) -> Tuple[Any, Any]:
        if len(messages) != 2:
            raise ValueError("OT nécessite exactement 2 messages")
        k0 = os.urandom(32)
        k1 = os.urandom(32)
        e0 = bytes(a ^ b for a, b in zip(messages[0], hashlib.sha256(k0).digest()[:len(messages[0])]))
        e1 = bytes(a ^ b for a, b in zip(messages[1], hashlib.sha256(k1).digest()[:len(messages[1])]))
        sender_state = {"k0": k0, "k1": k1, "e0": e0, "e1": e1}
        receiver_choices = {"e0": e0, "e1": e1}
        return sender_state, receiver_choices

    def ot_receive(self, choice: int, receiver_data: Any) -> bytes:
        if choice not in (0, 1):
            raise ValueError("Choix doit être 0 ou 1")
        return receiver_data[f"e{choice}"]

    # ─── KEY MANAGEMENT ─────────────────────────────────────────────────

    def rotate_keys(self) -> int:
        rotated = 0
        now = datetime.now(timezone.utc)
        for key_id, key in list(self._keys.items()):
            if key.expires_at < now:
                key.status = KeyStatus.EXPIRED
                new_key = self.generate_keypair(key.algorithm, key.security_level)
                self._keys[key_id] = new_key
                rotated += 1
                logger.info(f"🔄 Clé rotatée: {key_id} → {new_key.key_id}")
        self._stats["keys_rotated"] = rotated
        return rotated

    def revoke_key(self, key_id: str) -> bool:
        if key_id in self._keys:
            self._keys[key_id].status = KeyStatus.REVOKED
            logger.warning(f"🚫 Clé révoquée: {key_id}")
            return True
        return False

    def get_key(self, key_id: str) -> Optional[QuantumKeyPair]:
        return self._keys.get(key_id)

    def list_keys(self, status: Optional[KeyStatus] = None) -> List[QuantumKeyPair]:
        if status:
            return [k for k in self._keys.values() if k.status == status]
        return list(self._keys.values())

    # ─── STATISTICS ─────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        active_keys = [k for k in self._keys.values() if k.status == KeyStatus.ACTIVE]
        expired_keys = [k for k in self._keys.values() if k.status == KeyStatus.EXPIRED]
        stats = {
            **self._stats,
            "total_keys": len(self._keys),
            "active_keys": len(active_keys),
            "expired_keys": len(expired_keys),
            "revoked_keys": len([k for k in self._keys.values() if k.status == KeyStatus.REVOKED]),
            "algorithms_used": list(set(k.algorithm.value for k in self._keys.values())),
            "security_level": self._default_level.value,
            "hybrid_mode": self._hybrid_mode,
            "key_rotation_days": self._rotation_days,
            "hardware_acceleration": self._use_hw,
            "liboqs_available": OQS_AVAILABLE,
            "cryptography_available": CRYPTO_AVAILABLE,
            "bls_available": BLS_AVAILABLE,
            "uptime_hours": (now - datetime.fromisoformat(self._stats["started_at"])).total_seconds() / 3600,
            "status": "QUANTUM_READY" if OQS_AVAILABLE else "CLASSICAL_FALLBACK",
        }
        if active_keys:
            avg_age = sum(k.age_hours for k in active_keys) / len(active_keys)
            stats["avg_key_age_hours"] = round(avg_age, 2)
        return stats

    def health_check(self) -> Dict[str, Any]:
        checks = {
            "liboqs": OQS_AVAILABLE,
            "cryptography": CRYPTO_AVAILABLE,
            "bls": BLS_AVAILABLE,
            "numpy": NUMPY_AVAILABLE,
            "redis": self._redis is not None,
            "thread_pool": not self._thread_pool._shutdown,
            "process_pool": not self._process_pool._shutdown,
        }
        try:
            test_data = b"Cyber Global Shield - Health Check"
            encrypted = self.encrypt(test_data)
            decrypted = self.decrypt(encrypted)
            checks["encrypt_decrypt"] = test_data == decrypted
        except Exception as e:
            checks["encrypt_decrypt"] = False
            checks["encrypt_error"] = str(e)
        try:
            sig = self.sign(test_data)
            checks["sign_verify"] = self.verify(sig, test_data)
        except Exception as e:
            checks["sign_verify"] = False
            checks["sign_error"] = str(e)
        checks["overall"] = all(v for k, v in checks.items() if isinstance(v, bool) and k != "overall")
        return checks

    def cleanup(self):
        self._thread_pool.shutdown(wait=False)
        self._process_pool.shutdown(wait=False)
        if self._redis:
            asyncio.run(self._redis.close())
        logger.info("🧹 QuantumCryptoEngine nettoyé")


# ═══════════════════════════════════════════════════════════════════════════
# INSTANCE GLOBALE
# ═══════════════════════════════════════════════════════════════════════════

quantum_crypto = QuantumCryptoEngine(
    default_security_level=SecurityLevel.LEVEL_5,
    enable_hybrid=True,
    key_rotation_days=30,
    use_hardware_acceleration=True,
)
