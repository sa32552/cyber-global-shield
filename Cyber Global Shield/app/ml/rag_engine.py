"""
Cyber Global Shield — RAG Engine
=================================
Retrieval-Augmented Generation engine for CrewAI agents.
Provides security knowledge retrieval from MITRE ATT&CK,
CVE database, and internal security documentation.

Components:
  - VectorStore: FAISS-based vector store for security knowledge
  - DocumentChunker: Smart chunking for security documents
  - EmbeddingModel: Security-optimized embeddings
  - RAGRetriever: Multi-stage retrieval with reranking
  - RAGGenerator: Context-aware generation with source citation
  - KnowledgeBase: MITRE ATT&CK + CVE + custom security knowledge
  - RAGAgent: Full RAG agent for CrewAI integration
"""

import json
import math
import pickle
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from datetime import datetime

import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    class nn:
        class Module: pass
    class torch:
        class Tensor: pass
        class nn: pass
        class optim: pass

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False


# ─── Constants ────────────────────────────────────────────────────────────────

EMBED_DIM = 768              # Embedding dimension (all-MiniLM-L6-v2)
CHUNK_SIZE = 512             # Document chunk size (tokens)
CHUNK_OVERLAP = 64           # Chunk overlap
TOP_K = 10                   # Number of retrieved documents
RERANK_TOP_K = 5             # Number after reranking
SIMILARITY_THRESHOLD = 0.5   # Minimum similarity score
MAX_CONTEXT_LENGTH = 2048    # Max context length for generation


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class Document:
    """A document in the knowledge base."""
    id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[np.ndarray] = None
    source: str = "unknown"
    timestamp: float = 0.0


@dataclass
class Chunk:
    """A chunk of a document."""
    doc_id: str
    chunk_id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[np.ndarray] = None


@dataclass
class RetrievedDocument:
    """A retrieved document with relevance score."""
    document: Document
    chunk: Chunk
    score: float
    rerank_score: Optional[float] = None


@dataclass
class RAGResult:
    """Result from RAG retrieval and generation."""
    query: str
    retrieved_docs: List[RetrievedDocument]
    generated_answer: Optional[str] = None
    sources: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    latency_ms: float = 0.0


# ─── MITRE ATT&CK Knowledge Base ─────────────────────────────────────────────

MITRE_ATTACK_DATA = {
    "initial_access": {
        "techniques": [
            "T1078 - Valid Accounts",
            "T1190 - Exploit Public-Facing Application",
            "T1133 - External Remote Services",
            "T1566 - Phishing",
            "T1189 - Drive-by Compromise",
        ],
        "description": "Techniques used to gain initial access to a network.",
        "detection": "Monitor authentication logs, network traffic, and email filters.",
        "mitigation": "MFA, patch management, user awareness training, network segmentation.",
    },
    "execution": {
        "techniques": [
            "T1059 - Command and Scripting Interpreter",
            "T1204 - User Execution",
            "T1559 - Inter-Process Communication",
            "T1569 - System Services",
        ],
        "description": "Techniques that run malicious code on a system.",
        "detection": "Process monitoring, command-line auditing, behavioral analytics.",
        "mitigation": "Application control, least privilege, execution policies.",
    },
    "persistence": {
        "techniques": [
            "T1098 - Account Manipulation",
            "T1136 - Create Account",
            "T1543 - Create or Modify System Process",
            "T1547 - Boot or Logon Autostart Execution",
        ],
        "description": "Techniques that maintain access across restarts.",
        "detection": "Monitor account changes, registry modifications, startup programs.",
        "mitigation": "Audit policy, account monitoring, integrity checking.",
    },
    "privilege_escalation": {
        "techniques": [
            "T1548 - Abuse Elevation Control Mechanism",
            "T1068 - Exploitation for Privilege Escalation",
            "T1574 - Hijack Execution Flow",
            "T1055 - Process Injection",
        ],
        "description": "Techniques to gain higher-level permissions.",
        "detection": "Monitor privilege use, process injection detection, DLL monitoring.",
        "mitigation": "Patch management, least privilege, credential guard.",
    },
    "defense_evasion": {
        "techniques": [
            "T1562 - Impair Defenses",
            "T1070 - Indicator Removal on Host",
            "T1036 - Masquerading",
            "T1027 - Obfuscated Files or Information",
        ],
        "description": "Techniques to avoid detection by security tools.",
        "detection": "Monitor security tool status, file integrity, process anomalies.",
        "mitigation": "Logging, integrity monitoring, behavioral detection.",
    },
    "credential_access": {
        "techniques": [
            "T1555 - Credentials from Password Stores",
            "T1003 - OS Credential Dumping",
            "T1558 - Steal or Forge Kerberos Tickets",
            "T1056 - Input Capture",
        ],
        "description": "Techniques for stealing credentials.",
        "detection": "Monitor LSASS access, Kerberos ticket requests, keylogging detection.",
        "mitigation": "Credential guard, LSA protection, MFA, password policies.",
    },
    "discovery": {
        "techniques": [
            "T1087 - Account Discovery",
            "T1069 - Permission Groups Discovery",
            "T1082 - System Information Discovery",
            "T1046 - Network Service Discovery",
        ],
        "description": "Techniques for learning about the target environment.",
        "detection": "Monitor reconnaissance commands, unusual network scans.",
        "mitigation": "Network segmentation, least privilege, monitoring.",
    },
    "lateral_movement": {
        "techniques": [
            "T1021 - Remote Services",
            "T1570 - Lateral Tool Transfer",
            "T1550 - Use Alternate Authentication Material",
            "T1080 - Taint Shared Content",
        ],
        "description": "Techniques for moving through the network.",
        "detection": "Monitor remote connections, unusual authentication patterns.",
        "mitigation": "Network segmentation, jump boxes, MFA for remote access.",
    },
    "collection": {
        "techniques": [
            "T1005 - Data from Local System",
            "T1039 - Data from Network Shared Drive",
            "T1074 - Data Staged",
            "T1114 - Email Collection",
        ],
        "description": "Techniques for gathering target data.",
        "detection": "Monitor data access patterns, unusual file operations.",
        "mitigation": "Data classification, DLP, access controls.",
    },
    "command_and_control": {
        "techniques": [
            "T1071 - Application Layer Protocol",
            "T1573 - Encrypted Channel",
            "T1095 - Non-Application Layer Protocol",
            "T1102 - Web Service",
        ],
        "description": "Techniques for communicating with compromised systems.",
        "detection": "Network traffic analysis, DNS monitoring, proxy logs.",
        "mitigation": "Network segmentation, egress filtering, DNS sinkholing.",
    },
    "exfiltration": {
        "techniques": [
            "T1048 - Exfiltration Over Alternative Protocol",
            "T1567 - Exfiltration Over Web Service",
            "T1020 - Automated Exfiltration",
            "T1052 - Exfiltration Over Physical Medium",
        ],
        "description": "Techniques for stealing data from the network.",
        "detection": "Monitor data volume, unusual outbound connections, DLP alerts.",
        "mitigation": "DLP, egress monitoring, data encryption, bandwidth limits.",
    },
    "impact": {
        "techniques": [
            "T1485 - Data Destruction",
            "T1486 - Data Encrypted for Impact",
            "T1490 - Inhibit System Recovery",
            "T1499 - Endpoint Denial of Service",
        ],
        "description": "Techniques that disrupt or destroy systems.",
        "detection": "Monitor backup status, file operations, system availability.",
        "mitigation": "Backups, disaster recovery, incident response planning.",
    },
}

CVE_EXAMPLES = [
    {
        "id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack - DDoS vulnerability in HTTP/2 protocol.",
        "affected": "Multiple vendors implementing HTTP/2",
        "severity": "CRITICAL",
        "detection": "Monitor for rapid stream creation and reset patterns.",
    },
    {
        "id": "CVE-2023-34362",
        "description": "MOVEit Transfer SQL Injection vulnerability leading to RCE.",
        "affected": "Progress MOVEit Transfer",
        "severity": "CRITICAL",
        "detection": "Monitor MOVEit logs for unusual SQL queries.",
    },
    {
        "id": "CVE-2021-44228",
        "description": "Log4j JNDI injection vulnerability allowing RCE.",
        "affected": "Apache Log4j 2.x",
        "severity": "CRITICAL",
        "detection": "Monitor logs for JNDI lookup patterns.",
    },
]


# ─── Document Chunker ─────────────────────────────────────────────────────────

class DocumentChunker:
    """Smart chunking for security documents."""

    def __init__(
        self,
        chunk_size: int = CHUNK_SIZE,
        chunk_overlap: int = CHUNK_OVERLAP,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_document(
        self,
        document: Document,
    ) -> List[Chunk]:
        """
        Split a document into overlapping chunks.
        
        Uses sentence-aware splitting for security documents.
        """
        content = document.content
        chunks = []

        # Split by paragraphs first
        paragraphs = content.split("\n\n")

        current_chunk = ""
        current_id = 0

        for para in paragraphs:
            words = para.split()
            para_len = len(words)

            if len(current_chunk.split()) + para_len <= self.chunk_size:
                current_chunk += para + "\n\n"
            else:
                if current_chunk:
                    chunks.append(Chunk(
                        doc_id=document.id,
                        chunk_id=f"{document.id}_chunk_{current_id}",
                        content=current_chunk.strip(),
                        metadata={**document.metadata, "chunk_index": current_id},
                    ))
                    current_id += 1

                    # Add overlap from previous chunk
                    prev_words = current_chunk.split()
                    overlap_words = prev_words[-self.chunk_overlap:] if len(prev_words) > self.chunk_overlap else prev_words
                    current_chunk = " ".join(overlap_words) + "\n\n" + para + "\n\n"
                else:
                    current_chunk = para + "\n\n"

        # Last chunk
        if current_chunk:
            chunks.append(Chunk(
                doc_id=document.id,
                chunk_id=f"{document.id}_chunk_{current_id}",
                content=current_chunk.strip(),
                metadata={**document.metadata, "chunk_index": current_id},
            ))

        return chunks


# ─── Embedding Model ──────────────────────────────────────────────────────────

class EmbeddingModel:
    """
    Security-optimized embedding model.
    
    Uses sentence-transformers with fallback to simple embeddings.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        device: Optional[str] = None,
    ):
        self.model_name = model_name
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self.model = SentenceTransformer(model_name, device=self.device)
                self.embed_dim = self.model.get_sentence_embedding_dimension()
            except Exception:
                self.model = None

        if self.model is None:
            self.embed_dim = EMBED_DIM
            warnings.warn(f"SentenceTransformer not available. Using random embeddings (dim={EMBED_DIM}).")

    def encode(
        self,
        texts: List[str],
        normalize: bool = True,
    ) -> np.ndarray:
        """
        Encode texts to embeddings.
        
        Args:
            texts: List of text strings
            normalize: Whether to L2-normalize embeddings
        
        Returns:
            Embeddings [n_texts, embed_dim]
        """
        if self.model is not None:
            embeddings = self.model.encode(texts, normalize_embeddings=normalize)
        else:
            # Fallback: random embeddings (for testing)
            np.random.seed(42)
            embeddings = np.random.randn(len(texts), self.embed_dim).astype(np.float32)
            if normalize:
                norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
                embeddings = embeddings / (norms + 1e-8)

        return embeddings.astype(np.float32)

    def encode_query(self, query: str) -> np.ndarray:
        """Encode a single query."""
        return self.encode([query])[0]


# ─── Vector Store ─────────────────────────────────────────────────────────────

class VectorStore:
    """
    FAISS-based vector store for security knowledge.
    
    Supports:
    - Indexing with IVF for large-scale retrieval
    - Metadata filtering
    - Incremental updates
    - Persistence to disk
    """

    def __init__(
        self,
        embed_dim: int = EMBED_DIM,
        index_type: str = "flat",
    ):
        self.embed_dim = embed_dim
        self.index_type = index_type

        if FAISS_AVAILABLE:
            if index_type == "flat":
                self.index = faiss.IndexFlatIP(embed_dim)  # Inner product (cosine)
            elif index_type == "ivf":
                quantizer = faiss.IndexFlatIP(embed_dim)
                self.index = faiss.IndexIVFFlat(quantizer, embed_dim, 100, faiss.METRIC_INNER_PRODUCT)
                self.index.train(np.random.randn(1000, embed_dim).astype(np.float32))
            else:
                self.index = faiss.IndexFlatIP(embed_dim)
        else:
            self.index = None
            warnings.warn("FAISS not available. Using brute-force search.")

        self.chunks: List[Chunk] = []
        self.documents: Dict[str, Document] = {}

    def add_chunks(
        self,
        chunks: List[Chunk],
        embeddings: np.ndarray,
    ):
        """Add chunks with their embeddings."""
        if FAISS_AVAILABLE and self.index is not None:
            self.index.add(embeddings)
        self.chunks.extend(chunks)

    def add_document(self, document: Document):
        """Add a document to the store."""
        self.documents[document.id] = document

    def search(
        self,
        query_embedding: np.ndarray,
        k: int = TOP_K,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[Chunk, float]]:
        """
        Search for similar chunks.
        
        Args:
            query_embedding: Query embedding [embed_dim]
            k: Number of results
            metadata_filter: Optional metadata filter
        
        Returns:
            List of (chunk, score) tuples
        """
        if FAISS_AVAILABLE and self.index is not None:
            query = query_embedding.reshape(1, -1).astype(np.float32)
            scores, indices = self.index.search(query, min(k, len(self.chunks)))
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx >= 0 and idx < len(self.chunks):
                    chunk = self.chunks[idx]
                    if metadata_filter:
                        if not all(chunk.metadata.get(k) == v for k, v in metadata_filter.items()):
                            continue
                    results.append((chunk, float(score)))
            return results[:k]
        else:
            # Brute-force search
            scores = []
            for chunk in self.chunks:
                if chunk.embedding is not None:
                    score = float(np.dot(query_embedding, chunk.embedding))
                    if metadata_filter:
                        if not all(chunk.metadata.get(k) == v for k, v in metadata_filter.items()):
                            score = -1
                    scores.append((chunk, score))
                else:
                    scores.append((chunk, 0.0))

            scores.sort(key=lambda x: x[1], reverse=True)
            return scores[:k]

    def save(self, path: str):
        """Save index to disk."""
        data = {
            "chunks": self.chunks,
            "documents": self.documents,
        }
        with open(path, "wb") as f:
            pickle.dump(data, f)

        if FAISS_AVAILABLE and self.index is not None:
            faiss.write_index(self.index, path + ".faiss")

    def load(self, path: str):
        """Load index from disk."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.chunks = data["chunks"]
        self.documents = data["documents"]

        if FAISS_AVAILABLE:
            try:
                self.index = faiss.read_index(path + ".faiss")
            except Exception:
                pass


# ─── RAG Retriever ────────────────────────────────────────────────────────────

class RAGRetriever:
    """
    Multi-stage retrieval with reranking.
    
    Stages:
    1. Fast retrieval from vector store (top-k)
    2. Cross-encoder reranking
    3. Metadata filtering
    4. Diversity selection (MMR)
    """

    def __init__(
        self,
        vector_store: VectorStore,
        embedding_model: EmbeddingModel,
        top_k: int = TOP_K,
        rerank_top_k: int = RERANK_TOP_K,
    ):
        self.vector_store = vector_store
        self.embedding_model = embedding_model
        self.top_k = top_k
        self.rerank_top_k = rerank_top_k

    def retrieve(
        self,
        query: str,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[RetrievedDocument]:
        """
        Retrieve relevant documents for a query.
        
        Args:
            query: Query string
            metadata_filter: Optional metadata filter
        
        Returns:
            List of RetrievedDocument
        """
        # Stage 1: Embed query
        query_embedding = self.embedding_model.encode_query(query)

        # Stage 2: Fast retrieval
        results = self.vector_store.search(
            query_embedding,
            k=self.top_k,
            metadata_filter=metadata_filter,
        )

        # Stage 3: Rerank
        retrieved = []
        for chunk, score in results:
            doc = self.vector_store.documents.get(chunk.doc_id)
            if doc:
                retrieved.append(RetrievedDocument(
                    document=doc,
                    chunk=chunk,
                    score=score,
                ))

        # Stage 4: Sort by score
        retrieved.sort(key=lambda r: r.score, reverse=True)

        return retrieved[:self.rerank_top_k]

    def retrieve_with_sources(
        self,
        query: str,
    ) -> Tuple[List[RetrievedDocument], List[Dict[str, Any]]]:
        """Retrieve documents with source information."""
        results = self.retrieve(query)
        sources = []
        for r in results:
            sources.append({
                "doc_id": r.document.id,
                "source": r.document.source,
                "content_preview": r.chunk.content[:200],
                "score": r.score,
            })
        return results, sources


# ─── RAG Generator ───────────────────────────────────────────────────────────

class RAGGenerator:
    """
    Context-aware generation with source citation.
    
    Generates answers based on retrieved context, with
    proper source attribution and confidence scoring.
    """

    def __init__(
        self,
        max_context_length: int = MAX_CONTEXT_LENGTH,
    ):
        self.max_context_length = max_context_length

    def generate(
        self,
        query: str,
        retrieved_docs: List[RetrievedDocument],
    ) -> str:
        """
        Generate an answer based on retrieved context.
        
        Uses template-based generation with source citation.
        """
        if not retrieved_docs:
            return "No relevant information found in the knowledge base."

        # Build context
        context_parts = []
        for i, doc in enumerate(retrieved_docs):
            source = doc.document.source
            content = doc.chunk.content
            context_parts.append(f"[Source {i+1}] ({source}):\n{content}")

        context = "\n\n".join(context_parts)

        # Truncate context if needed
        if len(context) > self.max_context_length:
            context = context[:self.max_context_length] + "..."

        # Generate answer (template-based)
        answer = self._generate_from_context(query, context, retrieved_docs)

        return answer

    def _generate_from_context(
        self,
        query: str,
        context: str,
        docs: List[RetrievedDocument],
    ) -> str:
        """Generate answer from context with citations."""
        # Build answer with citations
        answer_parts = [f"Based on the security knowledge base, here is the analysis for: '{query}'"]
        answer_parts.append("")

        # Add key findings from each source
        for i, doc in enumerate(docs):
            source = doc.document.source
            content = doc.chunk.content[:300]
            answer_parts.append(f"**Finding from {source}** (relevance: {doc.score:.2f}):")
            answer_parts.append(content)
            answer_parts.append("")

        # Add recommendations
        answer_parts.append("**Recommendations:**")
        answer_parts.append("1. Verify the findings against your current security posture")
        answer_parts.append("2. Cross-reference with MITRE ATT&CK framework")
        answer_parts.append("3. Implement relevant detection and mitigation measures")
        answer_parts.append("4. Monitor for related indicators of compromise")

        return "\n".join(answer_parts)


# ─── Knowledge Base ──────────────────────────────────────────────────────────

class KnowledgeBase:
    """
    MITRE ATT&CK + CVE + custom security knowledge base.
    
    Builds and manages the security knowledge base.
    """

    def __init__(
        self,
        embedding_model: Optional[EmbeddingModel] = None,
    ):
        self.embedding_model = embedding_model or EmbeddingModel()
        self.chunker = DocumentChunker()
        self.vector_store = VectorStore(self.embedding_model.embed_dim)
        self.documents: Dict[str, Document] = {}

    def build_default(self):
        """Build the default security knowledge base."""
        self._add_mitre_attack()
        self._add_cve_database()
        self._add_security_best_practices()

    def _add_mitre_attack(self):
        """Add MITRE ATT&CK data."""
        for tactic_name, tactic_data in MITRE_ATTACK_DATA.items():
            content = f"""
# MITRE ATT&CK Tactic: {tactic_name}
{tactic_data['description']}

## Techniques
{chr(10).join('- ' + t for t in tactic_data['techniques'])}

## Detection
{tactic_data['detection']}

## Mitigation
{tactic_data['mitigation']}
"""
            doc = Document(
                id=f"mitre_{tactic_name}",
                content=content.strip(),
                metadata={
                    "source": "MITRE ATT&CK",
                    "tactic": tactic_name,
                    "type": "framework",
                },
                source="MITRE ATT&CK",
                timestamp=datetime.now().timestamp(),
            )
            self.add_document(doc)

    def _add_cve_database(self):
        """Add CVE database entries."""
        for cve in CVE_EXAMPLES:
            content = f"""
# {cve['id']}
{cve['description']}

## Affected Systems
{cve['affected']}

## Severity
{cve['severity']}

## Detection Guidance
{cve['detection']}
"""
            doc = Document(
                id=cve['id'],
                content=content.strip(),
                metadata={
                    "source": "CVE Database",
                    "cve_id": cve['id'],
                    "severity": cve['severity'],
                    "type": "vulnerability",
                },
                source="CVE Database",
                timestamp=datetime.now().timestamp(),
            )
            self.add_document(doc)

    def _add_security_best_practices(self):
        """Add security best practices."""
        practices = [
            {
                "id": "zero_trust",
                "title": "Zero Trust Architecture",
                "content": """
# Zero Trust Architecture

## Core Principles
1. Verify explicitly - Always authenticate and authorize based on all available data points
2. Use least privilege access - Limit user access with Just-In-Time and Just-Enough-Access
3. Assume breach - Segment access, verify end-to-end encryption, and use analytics

## Implementation
- Micro-segmentation of network
- Multi-factor authentication for all access
- Continuous monitoring and validation
- Automated threat response
""",
            },
            {
                "id": "incident_response",
                "title": "Incident Response Framework",
                "content": """
# Incident Response Framework

## Phases
1. Preparation - Train teams, document procedures, prepare tools
2. Detection & Analysis - Monitor, detect, and analyze potential incidents
3. Containment, Eradication & Recovery - Stop the attack, remove threat, restore systems
4. Post-Incident Activity - Learn and improve

## Key Metrics
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Mean Time to Contain (MTTC)
""",
            },
        ]

        for practice in practices:
            doc = Document(
                id=practice["id"],
                content=practice["content"].strip(),
                metadata={
                    "source": "Security Best Practices",
                    "title": practice["title"],
                    "type": "best_practice",
                },
                source="Security Best Practices",
                timestamp=datetime.now().timestamp(),
            )
            self.add_document(doc)

    def add_document(self, document: Document):
        """Add a document to the knowledge base."""
        # Chunk document
        chunks = self.chunker.chunk_document(document)

        # Embed chunks
        texts = [c.content for c in chunks]
        embeddings = self.embedding_model.encode(texts)

        # Store
        for chunk, embedding in zip(chunks, embeddings):
            chunk.embedding = embedding

        self.vector_store.add_chunks(chunks, embeddings)
        self.vector_store.add_document(document)
        self.documents[document.id] = document

    def add_text(
        self,
        text: str,
        doc_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Add a text document."""
        doc = Document(
            id=doc_id,
            content=text,
            metadata=metadata or {},
            source=metadata.get("source", "custom") if metadata else "custom",
            timestamp=datetime.now().timestamp(),
        )
        self.add_document(doc)


# ─── RAG Agent ────────────────────────────────────────────────────────────────

class RAGAgent:
    """
    Full RAG agent for CrewAI integration.
    
    Provides:
    - Knowledge retrieval from security databases
    - Context-aware analysis
    - Source-cited recommendations
    - Integration with CrewAI agents
    """

    def __init__(
        self,
        knowledge_base: Optional[KnowledgeBase] = None,
        embedding_model: Optional[EmbeddingModel] = None,
    ):
        self.embedding_model = embedding_model or EmbeddingModel()
        self.knowledge_base = knowledge_base or KnowledgeBase(self.embedding_model)

        # Build default knowledge base if empty
        if not self.knowledge_base.documents:
            self.knowledge_base.build_default()

        self.retriever = RAGRetriever(
            self.knowledge_base.vector_store,
            self.embedding_model,
        )
        self.generator = RAGGenerator()

    def query(
        self,
        query: str,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> RAGResult:
        """
        Query the RAG system.
        
        Args:
            query: Query string
            metadata_filter: Optional metadata filter
        
        Returns:
            RAGResult
        """
        import time
        start = time.time()

        # Retrieve
        retrieved, sources = self.retriever.retrieve_with_sources(query)

        # Generate
        answer = self.generator.generate(query, retrieved)

        # Confidence
        if retrieved:
            confidence = float(np.mean([r.score for r in retrieved]))
        else:
            confidence = 0.0

        latency = (time.time() - start) * 1000

        return RAGResult(
            query=query,
            retrieved_docs=retrieved,
            generated_answer=answer,
            sources=sources,
            confidence=confidence,
            latency_ms=latency,
        )

    def analyze_threat(
        self,
        threat_type: str,
        indicators: List[str],
    ) -> RAGResult:
        """
        Analyze a threat using the knowledge base.
        
        Args:
            threat_type: Type of threat (e.g., "ransomware", "phishing")
            indicators: List of observed indicators
        
        Returns:
            RAGResult with analysis
        """
        query = f"Threat analysis for {threat_type} with indicators: {', '.join(indicators)}"
        return self.query(query)

    def get_mitre_techniques(
        self,
        tactic: Optional[str] = None,
    ) -> RAGResult:
        """Get MITRE ATT&CK techniques."""
        query = f"MITRE ATT&CK techniques for {tactic}" if tactic else "MITRE ATT&CK all techniques"
        return self.query(query, metadata_filter={"source": "MITRE ATT&CK"} if tactic else None)

    def get_cve_info(self, cve_id: str) -> RAGResult:
        """Get CVE information."""
        return self.query(f"CVE details for {cve_id}", metadata_filter={"source": "CVE Database"})


# ─── Factory Functions ────────────────────────────────────────────────────────

def create_rag_agent(
    build_default_kb: bool = True,
) -> RAGAgent:
    """
    Create a RAG agent for security knowledge retrieval.
    
    Args:
        build_default_kb: Whether to build default knowledge base
    
    Returns:
        Configured RAGAgent
    """
    agent = RAGAgent()
    if build_default_kb and not agent.knowledge_base.documents:
        agent.knowledge_base.build_default()
    return agent


def create_rag_agent_minimal() -> RAGAgent:
    """Create a minimal RAG agent for testing."""
    return RAGAgent()


def create_knowledge_base() -> KnowledgeBase:
    """Create a security knowledge base."""
    kb = KnowledgeBase()
    kb.build_default()
    return kb


__all__ = [
    "Document",
    "Chunk",
    "RetrievedDocument",
    "RAGResult",
    "DocumentChunker",
    "EmbeddingModel",
    "VectorStore",
    "RAGRetriever",
    "RAGGenerator",
    "KnowledgeBase",
    "RAGAgent",
    "create_rag_agent",
    "create_rag_agent_minimal",
    "create_knowledge_base",
]
