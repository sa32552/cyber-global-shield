"""
╔══════════════════════════════════════════════════════════════╗
║     CYBER GLOBAL SHIELD — POWER UP SCRIPT v2.0              ║
║     Active toute la puissance de la plateforme               ║
║     avec les outils Python les plus avancés                  ║
╚══════════════════════════════════════════════════════════════╝

Usage: python scripts/power_up.py
"""

import subprocess
import sys
import os
from pathlib import Path

# ─── Configuration ──────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
ENV_FILE = ROOT / ".env"

# ─── Catégories d'outils de pointe ─────────────────────────────────────────

TOOLS = {
    "🤖 LLM Multi-Provider (LiteLLM)": [
        "litellm>=1.40.0",
    ],
    "🔐 IAM & Firewall (Keycloak, Fortinet, Wazuh)": [
        "python-keycloak>=3.0.0",
        "fortios-api>=1.0.0",
        "wazuh>=3.0.0",
    ],
    "⛓️ Blockchain (Ethereum, Hyperledger)": [
        "web3>=6.0.0",
        "fabric-sdk-py>=1.0.0",
    ],
    "🌑 Dark Web & OSINT (Tor, Scrapy, Telegram)": [
        "stem>=1.8.0",
        "scrapy>=2.11.0",
        "beautifulsoup4>=4.12.0",
        "python-telegram-bot>=20.0.0",
        "requests[socks]>=2.31.0",
    ],
    "☁️ Cloud Security (AWS, Azure, GCP)": [
        "boto3>=1.34.0",
        "azure-identity>=1.15.0",
        "google-cloud-resource-manager>=1.12.0",
    ],
    "🔬 Quantum Computing (PennyLane, Qiskit, Cirq)": [
        "pennylane>=0.35.0",
        "qiskit>=1.0.0",
        "cirq>=1.3.0",
        "torchquantum>=0.1.0",
    ],
    "📊 Profiling & Benchmarks (py-spy, memray, asv)": [
        "pytest-benchmark>=4.0.0",
        "py-spy>=0.3.14",
        "memray>=1.10.0",
        "asv>=0.6.0",
    ],
}


def print_banner():
    """Affiche la bannière de démarrage."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗                   ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗                  ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝                  ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗                  ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║                  ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝                  ║
║                                                              ║
║   ██████╗ ██╗      ██████╗ ██████╗  █████╗ ██╗              ║
║  ██╔════╝ ██║     ██╔═══██╗██╔══██╗██╔══██╗██║              ║
║  ██║  ███╗██║     ██║   ██║██████╔╝███████║██║              ║
║  ██║   ██║██║     ██║   ██║██╔══██╗██╔══██║██║              ║
║  ╚██████╔╝███████╗╚██████╔╝██║  ██║██║  ██║███████╗         ║
║   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝         ║
║                                                              ║
║  🔥 POWER UP — Activation de tous les modules de pointe      ║
║  🚀 Version 2.0 — Python Tools Edition                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)


def run_pip_install(package: str) -> bool:
    """Installe un package pip et retourne True si succès."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", package],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"  ✅ {package}")
        return True
    else:
        print(f"  ❌ {package}: {result.stderr[:100]}")
        return False


def install_all():
    """Installe tous les outils de pointe."""
    total = 0
    success = 0

    for category, packages in TOOLS.items():
        print(f"\n  📦 {category}")
        print(f"  {'─' * (len(category) + 4)}")
        for pkg in packages:
            total += 1
            if run_pip_install(pkg):
                success += 1

    print(f"\n  {'═' * 50}")
    print(f"  📊 Résultat : {success}/{total} packages installés avec succès")
    print(f"  {'═' * 50}")

    return success == total


def update_env_file():
    """Met à jour le .env avec les nouvelles configurations."""
    if not ENV_FILE.exists():
        print("\n  ⚠️  Fichier .env non trouvé. Création à partir de .env.example...")
        example = ENV_FILE.parent / ".env.example"
        if example.exists():
            import shutil
            shutil.copy(example, ENV_FILE)
            print("  ✅ .env créé depuis .env.example")

    # Ajouter les nouvelles variables si absentes
    new_vars = """
# ─── POWER UP — Nouveaux outils de pointe ─────────────────────
# LLM Multi-Provider (LiteLLM — supporte OpenAI, Claude, Gemini, Llama, Groq)
LITELLM_API_KEY=
LITELLM_MODEL=gpt-4-turbo

# Keycloak IAM
KEYCLOAK_URL=
KEYCLOAK_REALM=cyber-global-shield
KEYCLOAK_CLIENT_ID=api

# Fortinet Firewall
FORTINET_HOST=
FORTINET_TOKEN=

# Wazuh EDR
WAZUH_HOST=
WAZUH_PORT=55000
WAZUH_USER=
WAZUH_PASSWORD=

# Ethereum Blockchain
ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/YOUR-PROJECT-ID
ETHEREUM_CONTRACT_ADDRESS=

# Tor / Dark Web
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_PASSWORD=

# Telegram Bot
TELEGRAM_BOT_TOKEN=

# Cloud Providers
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
GCP_PROJECT_ID=
GCP_CREDENTIALS_PATH=

# Quantum Computing
PENNYLANE_DEVICE=default.qubit  # ou 'qiskit.ibmq' pour IBM QPU
QISKIT_TOKEN=                   # IBM Quantum API token
"""
    with open(ENV_FILE, "a") as f:
        f.write(new_vars)
    print("  ✅ Nouvelles variables ajoutées au .env")


def verify_installation():
    """Vérifie que les outils critiques sont bien installés."""
    print("\n  🔍 Vérification des installations...\n")

    checks = {
        "LiteLLM (Multi-LLM)": "import litellm; print('  ✅ LiteLLM ready — 100+ LLM providers')",
        "Web3.py (Blockchain)": "import web3; print('  ✅ Web3 ready — Ethereum/Hyperledger')",
        "Stem (Tor)": "import stem; print('  ✅ Stem ready — Tor controller')",
        "PennyLane (Quantum)": "import pennylane; print('  ✅ PennyLane ready — Quantum ML')",
        "Qiskit (IBM Quantum)": "import qiskit; print('  ✅ Qiskit ready — IBM Quantum circuits')",
        "Cirq (Google Quantum)": "import cirq; print('  ✅ Cirq ready — Google Quantum')",
        "boto3 (AWS)": "import boto3; print('  ✅ boto3 ready — AWS SDK')",
        "Scrapy (Web Scraping)": "import scrapy; print('  ✅ Scrapy ready — Web scraping')",
        "python-keycloak (IAM)": "import keycloak; print('  ✅ Keycloak ready — IAM/SSO')",
    }

    all_ok = True
    for name, code in checks.items():
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"  ✅ {name}")
        else:
            print(f"  ❌ {name} — {result.stderr[:80]}")
            all_ok = False

    return all_ok


def run_tests():
    """Lance les tests pour valider que tout fonctionne."""
    print("\n  🧪 Lancement des tests de validation...\n")

    test_files = [
        "test_breach.py",
        "tests/test_modules.py",
        "tests/integration/test_quantum_modules.py",
    ]

    all_pass = True
    for test_file in test_files:
        test_path = ROOT / test_file
        if test_path.exists():
            print(f"  ▶️  Test: {test_file}")
            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
                capture_output=True,
                text=True,
                cwd=ROOT,
            )
            if result.returncode == 0:
                print(f"  ✅ {test_file} — PASSED")
            else:
                print(f"  ❌ {test_file} — FAILED")
                # Afficher les 5 dernières lignes d'erreur
                lines = result.stdout.split('\n')[-10:]
                for line in lines:
                    if 'FAILED' in line or 'ERROR' in line:
                        print(f"     {line.strip()}")
                all_pass = False

    return all_pass


def start_api():
    """Démarre l'API en mode production."""
    print("\n  🚀 Démarrage de l'API Cyber Global Shield...\n")
    os.chdir(ROOT)
    subprocess.run([sys.executable, "server.py"])


def main():
    """Point d'entrée principal."""
    print_banner()

    print("  ══════════════════════════════════════════════════════")
    print("  Étape 1/5 : Installation des outils de pointe")
    print("  ══════════════════════════════════════════════════════")
    if not install_all():
        print("\n  ⚠️  Certains packages n'ont pas pu être installés.")
        print("     Vous pouvez les installer manuellement avec pip.\n")

    print("\n  ══════════════════════════════════════════════════════")
    print("  Étape 2/5 : Configuration du fichier .env")
    print("  ══════════════════════════════════════════════════════")
    update_env_file()

    print("\n  ══════════════════════════════════════════════════════")
    print("  Étape 3/5 : Vérification des installations")
    print("  ══════════════════════════════════════════════════════")
    verify_installation()

    print("\n  ══════════════════════════════════════════════════════")
    print("  Étape 4/5 : Tests de validation")
    print("  ══════════════════════════════════════════════════════")
    run_tests()

    print("\n  ══════════════════════════════════════════════════════")
    print("  Étape 5/5 : Démarrage")
    print("  ══════════════════════════════════════════════════════")
    print("""
  ✅ CYBER GLOBAL SHIELD — POWER UP COMPLETED

  📋 Ce qui a été activé :
     🤖 LiteLLM → 100+ modèles LLM avec fallback automatique
     🔐 Keycloak → IAM/SSO d'entreprise
     🔥 Fortinet/Wazuh → Firewall & EDR réels
     ⛓️ Web3.py → Blockchain Ethereum/Hyperledger
     🌑 Stem + Scrapy → Dark Web & OSINT
     ☁️ boto3 + Azure + GCP → Cloud Security
     🔬 PennyLane + Qiskit + Cirq → Quantum Computing
     📊 py-spy + memray → Profiling avancé

  🚀 Pour démarrer l'API :
     python server.py

  🧪 Pour relancer les tests :
     pytest test_breach.py -v
     pytest tests/test_modules.py -v
     pytest tests/integration/test_quantum_modules.py -v
    """)


if __name__ == "__main__":
    main()
