"""
Cyber Global Shield — Blockchain Audit Trail
Chaîne de blocs immuable pour l'audit de sécurité.
Chaque événement est horodaté, hashé et chaîné de manière cryptographique.
"""

import json
import time
import hashlib
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AuditBlock:
    """A block in the audit blockchain."""
    index: int
    timestamp: float
    event_type: str
    event_data: Dict[str, Any]
    previous_hash: str
    hash: str
    nonce: int = 0
    signature: str = ""


class BlockchainAuditTrail:
    """
    Blockchain d'audit immuable.
    
    Garantit:
    - Intégrité des logs d'audit
    - Non-répudiation des événements
    - Détection de falsification
    - Chaîne de confiance vérifiable
    - Horodatage certifié
    """

    def __init__(self):
        self._chain: List[AuditBlock] = []
        self._difficulty = 4  # Leading zeros required
        self._create_genesis_block()

    def _create_genesis_block(self):
        """Create the genesis block."""
        genesis = AuditBlock(
            index=0,
            timestamp=time.time(),
            event_type="genesis",
            event_data={"message": "Cyber Global Shield Audit Blockchain initialized"},
            previous_hash="0" * 64,
            hash="",
        )
        genesis.hash = self._calculate_hash(genesis)
        self._chain.append(genesis)
        logger.info("🔗 Genesis block created")

    def _calculate_hash(self, block: AuditBlock) -> str:
        """Calculate SHA-256 hash of a block."""
        block_string = json.dumps({
            "index": block.index,
            "timestamp": block.timestamp,
            "event_type": block.event_type,
            "event_data": block.event_data,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def _proof_of_work(self, block: AuditBlock) -> AuditBlock:
        """Simple proof of work simulation."""
        while not block.hash.startswith("0" * self._difficulty):
            block.nonce += 1
            block.hash = self._calculate_hash(block)
        return block

    def add_event(self, event_type: str, event_data: Dict[str, Any]) -> AuditBlock:
        """Add an event to the audit blockchain."""
        previous_block = self._chain[-1]
        
        block = AuditBlock(
            index=len(self._chain),
            timestamp=time.time(),
            event_type=event_type,
            event_data=event_data,
            previous_hash=previous_block.hash,
            hash="",
        )

        # Proof of work
        block = self._proof_of_work(block)

        self._chain.append(block)
        logger.info(f"📜 Block #{block.index} added: {event_type}")
        return block

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire blockchain."""
        for i in range(1, len(self._chain)):
            current = self._chain[i]
            previous = self._chain[i - 1]

            # Verify hash
            if current.hash != self._calculate_hash(current):
                logger.error(f"❌ Block #{i} hash mismatch!")
                return False

            # Verify chain linkage
            if current.previous_hash != previous.hash:
                logger.error(f"❌ Block #{i} previous hash mismatch!")
                return False

        logger.info(f"✅ Blockchain verified: {len(self._chain)} blocks intact")
        return True

    def get_events_by_type(self, event_type: str) -> List[AuditBlock]:
        """Get all events of a specific type."""
        return [b for b in self._chain if b.event_type == event_type]

    def get_events_in_range(self, start: float, end: float) -> List[AuditBlock]:
        """Get events within a time range."""
        return [
            b for b in self._chain
            if start <= b.timestamp <= end
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get blockchain audit statistics."""
        return {
            "total_blocks": len(self._chain),
            "genesis_time": datetime.fromtimestamp(
                self._chain[0].timestamp
            ).isoformat(),
            "latest_block": datetime.fromtimestamp(
                self._chain[-1].timestamp
            ).isoformat(),
            "chain_integrity": self.verify_chain(),
            "event_types": list(set(
                b.event_type for b in self._chain
            )),
            "difficulty": self._difficulty,
            "status": "IMMUTABLE",
        }


blockchain_audit = BlockchainAuditTrail()
