# Zero-Trust AI Security Gateway & Firewalled RAG Stack

An enterprise-inspired, self-hosted AI security architecture enforcing **bi-directional LLM guardrails**, **PII/secret egress redaction**, **two-stage prompt-injection detection (Regex + local ONNX DeBERTa ML)**, **RAG poisoning defense**, and **hardened autonomous agent sandboxing** across repurposed bare-metal laptop hardware.

---

## Architecture Overview

This lab separates security enforcement from application workloads across two energy-efficient, AVX2-capable Kaby Lake laptops (~15W–30W TDP with built-in battery backup), orchestrated declaratively with **[Ansible](https://docs.ansible.com/)** and **[Docker Compose](https://docs.docker.com/compose/)**, validated with automated **[Promptfoo](https://www.promptfoo.dev/)** red-team evaluations:

```mermaid
---
config:
  theme: redux-dark-color
  layout: dagre
  look: classic
  lineColor: #f4f4f44d
    
---
flowchart LR
    subgraph ING["External Data"]
        EXT_DATA["External Untrusted Data<br/>(Webhooks / Scraped Pages)"]
        EXT_DATA@{ shape: cloud }
    end

    subgraph WIN["Windows 11 Workstation (192.168.1.20 / WSL2)"]
        IDE["VSCode + OpenCode"]
        PF["Promptfoo Red-Team Suite"]
    end

    subgraph S1["Server 1: Dell Latitude 7480 (192.168.1.10 | 16GB RAM)"]
        
        subgraph Z3["Zone 3: Hardened Autonomous Agent"]
            OC["OpenClaw Agent (:18789)<br/>read_only | cap_drop: ALL | uid 1000"]
            OC@{ shape: browser }
            SI["safe_ingest.py Air-Lock<br/>Fail-Closed + XML Delimiters"]
            SI --> OC
        end
        
        subgraph Z2["Zone 2: Zero-Trust Security Gateway"]
            LLM["LiteLLM Proxy (:4000)<br/>Virtual Keys + RPM Caps"]
            PG[("PostgreSQL 16<br/>(internal)")]
            PRES["Microsoft Presidio<br/>Egress PII/Secret DLP"]
            GR["Guardrails AI Hybrid Shield<br/>Stage 1 Regex + Stage 2 ONNX DeBERTa"]
            LLM --- PG
            LLM --- PRES
            LLM --- GR
        end

        OC -->|"openclaw_net"| LLM
    end

    subgraph S2["Server 2: Lenovo Ideapad 130-15IKB (192.168.1.11 | 12GB RAM)"]
        subgraph Z1["Zone 1: Firewalled RAG & Workloads"]
            RAG["Secure RAG API (:8090)"]
            QD[("Qdrant Vector DB<br/>(rag_internal only)")]
            ON["Open Notebook (:8502)"]
            ON@{ shape: browser }
            SDB[("SurrealDB v2")]
            SPK["Speakr Audio (:8899)"]
            SPK@{ shape: browser }
            RAG --- QD
            ON --- SDB
        end
    end

    subgraph CLOUD["Free-Tier Upstream APIs (TLS)"]
        API["Groq | Google Gemini 3.8 Flash | OpenRouter Auto-Free"]
        API@{ shape: cloud }
    end

    IDE -->|"UFW :4000"| LLM
    PF -->|"UFW :4000 / :8090"| LLM
    PF --> RAG
    RAG -->|"Embed & Validate"| LLM
    ON --> LLM
    SPK -->|"Whisper & Summary"| LLM
    PRES -->|"Sanitized Egress"| API
    ING -->|"Sanitized Ingress"| GR
    ING -->|"Sanitized Ingress"| SI
```

---

## Hardware Topology & Resource Engineering

* **Server 1 — AI Security Gateway & Sandboxed Agent (`Dell Latitude 7480` | Intel Core i5-7300U | 16 GB RAM):**
  * **LiteLLM Proxy (`2.5G` cap | Port `4000`):** Unified OpenAI-compatible control plane issuing scoped virtual API keys, per-client RPM rate limits, and automatic fallback routing across free-tier LLM and embedding providers.
  * **Microsoft Presidio (`3.5G` combined cap):** Scans outgoing prompts and code snippets (`pre_call`) for PII (`US_SSN`, `CREDIT_CARD`, `EMAIL_ADDRESS`) and hardcoded secrets (`AWS_ACCESS_KEY`), masking or blocking sensitive data before egress.
  * **Guardrails AI Two-Stage Hybrid Shield (`3.5G` cap):**
    * **Stage 1 (Deterministic Pre-Filter, `<1 ms`):** Strips and blocks zero-width Unicode smuggling (`\u200B`), normalizes homoglyphs (`NFKC`), and drops high-confidence shell-hijacking signatures before invoking neural inference.
    * **Stage 2 (Local ONNX DeBERTa-v3 Classifier, `~45 ms`):** Runs a pre-baked `optimum[onnxruntime]` export of `protectai/deberta-v3-base-prompt-injection-v2` on AVX2 CPU cores to catch paraphrased semantic injections that contain zero static regex keywords.
  * **Hardened OpenClaw Container (`2G` cap | Port `18789`):** Runs as non-root UID `1000:1000` with `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, UID-scoped `tmpfs` caches, zero `/var/run/docker.sock` access, and an isolated `openclaw_net` bridge.

* **Server 2 — Workloads & Firewalled RAG (`Lenovo Ideapad 130-15IKB` | Intel Core i7-8550U 8-Thread | 12 GB RAM):**
  * **Secure RAG API (`1G` cap | Port `8090`):** FastAPI ingestion and retrieval gateway that validates incoming documents against Server 1's two-stage Guardrails AI shield *before* generating embeddings or writing vectors.
  * **Qdrant Vector Database (`2G` cap):** Isolated inside an `internal: true` Docker network (`rag_internal`) so untrusted pipelines cannot inject poisoned embeddings directly.
  * **Open Notebook (`2.5G` cap | Port `8502`) & Speakr (`3G` cap | Port `8899`):** Research and 8-thread `int8` CPU Whisper transcription workloads routed strictly through Server 1's egress proxy.

---

## Threat Model & Mitigations

| Threat Vector | Attack Scenario | Control Implemented |
| :--- | :--- | :--- |
| **Sensitive Data Egress** | Developer pastes `.env` secrets or customer PII into coding assistant | Presidio `pre_call` hook blocks SSNs/AWS keys and masks emails/cards before upstream API calls |
| **Obfuscated & Signature Injections** | Scraped page hides `[SYSTEM]` commands or `\u200B` zero-width smuggling | Guardrails Stage 1 normalizes Unicode (`NFKC`) and blocks known hijacking signatures in `<1 ms` |
| **Paraphrased Semantic Injections** | Attacker uses polite, synonym-heavy phrasing to bypass static regex rules | Guardrails Stage 2 local ONNX `deberta-v3` classifier scores semantic intent (`threshold >= 0.85`) |
| **RAG Knowledge Poisoning** | Malicious document injected into vector DB to hijack future agent queries | `/ingest` endpoint enforces two-stage Guardrails AI validation prior to Qdrant vector upsert |
| **Runaway Agent / Quota Exhaustion** | Autonomous agent enters an infinite tool-calling loop | LiteLLM virtual keys enforce per-client `rpm_limit` isolation |
| **Container Breakout / Persistence** | Compromised OpenClaw agent attempts to modify binaries or escalate privileges | Non-root `1000:1000`, `read_only: true`, `cap_drop: [ALL]`, isolated bridge network, and `safe_ingest.py` XML boundaries |

---

## Deployment & Verification Guide

### Prerequisites
* **Control Node:** Linux host or Windows 11 with WSL2 (Ubuntu) running `ansible` (`>= 2.15`) and SSH key-based access to both target laptops.
* **Target Nodes (Ubuntu Server with Static DHCP IPs):**
  * **Server 1 (`192.168.1.10`):** Dell Latitude 7480 (16 GB RAM)
  * **Server 2 (`192.168.1.11`):** Lenovo Ideapad 130-15IKB (12 GB RAM)
* **API Keys:** Free-tier keys from Groq, Google AI Studio (Gemini), OpenRouter, or Mistral.

### Installing Ansible (Control Node Setup)

#### 1. Windows 11: Install WSL2 & Ubuntu (Skip if already on Linux)
Open **PowerShell as Administrator** and run:
```powershell
wsl --install -d Ubuntu
```
Reboot if prompted, launch **Ubuntu** from the Start Menu, and create your Linux username and password.

#### 2. Install Ansible & Required Collections (Ubuntu / WSL2)
```bash
sudo apt update
sudo apt install -y software-properties-common sshpass
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install -y ansible

# Install community.general collection for managing UFW firewall rules
ansible-galaxy collection install community.general
```

#### 3. Configure SSH Key Authentication
```bash
ssh-keygen -t ed25519 -C "ansible-control-node"
ssh-copy-id [user]@192.168.1.10
ssh-copy-id [user]@192.168.1.11
```

---

### Step 1: Configure Inventory & Secrets
1. Clone this repository onto your control node:
   ```bash
   git clone https://github.com/SnakesAndLadders/AILab.git
   cd ai-security-ansible
   ```
2. Verify `inventory.ini` matches your target laptop IPs (`192.168.1.10` and `192.168.1.11` in this case).
3. Edit `group_vars/all.yml` to add your upstream free-tier API keys and a strong `litellm_master_key`. *(Recommended: Encrypt secrets with `ansible-vault encrypt group_vars/all.yml`.)*
4. Test connectivity:
   ```bash
   ansible all -i inventory.ini -m ping
   ```

---

### Step 2: Deploy Server 1 (AI Security Gateway & Hardened OpenClaw)
Run the playbook targeting `security_gateway` first (configures 4 GB swap, disables lid-close suspend, installs Docker, builds the ONNX DeBERTa classifier, and configures UFW):
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --limit security_gateway --ask-become-pass
```

---

### Step 3: Issue Scoped Virtual API Keys
Generate isolated, rate-limited virtual keys via LiteLLM's `/key/generate` endpoint:

1. **Key for Server 2 (RAG Embeddings & Workloads):**
   ```bash
   curl -X POST 'http://[server1 IP]:4000/key/generate' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "server2-rag-apps", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 30}'
   ```
2. **Key for OpenClaw Agent Container (Strict RPM Cap):**
   ```bash
   curl -X POST 'http://[server1 IP]:4000/key/generate' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "openclaw-agent", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 10}'
   ```
3. **Key for Windows 11 Workstation (OpenCode & Promptfoo):**
   ```bash
   curl -X POST 'http://[server1 IP]:4000/key/generate' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "win11-opencode", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 30}'
   ```
4. Paste the generated keys for `server2_litellm_key` and `openclaw_litellm_key` into `group_vars/all.yml`.

---

### Step 4: Deploy Server 2 & Apply Virtual Keys Across Both Nodes
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --ask-become-pass
```

---

### Step 5: Run Automated Security & Compliance Checks
Verify UFW rules, swap health, internal container network isolation, `read_only` / `cap_drop: [ALL]` flags, and `safe_ingest.py` injection blocking:
```bash
ansible-playbook -i inventory.ini playbooks/verify_security.yml --ask-become-pass
```

---

### Step 6: Execute Promptfoo Red-Team Evaluation (Linux / WSL2 Control Node)
Install Node.js and Promptfoo on your control node to benchmark Egress DLP, Ingress Regex + ONNX ML detection, and RAG poisoning defense:

```bash
# Install fnm 
sudo apt update && sudo apt install -y curl unzip
curl -fsSL https://fnm.vercel.app/install | bash
source ~/.bashrc
# Download and install fnm:
curl -o- https://fnm.vercel.app/install | bash
# In lieu of restarting the shell
export PATH="$HOME/.local/share/fnm:$PATH"
eval "$(fnm env)"
# Download and install Node.js:
fnm install --use 26
# Verify the Node.js version:
node -v # Should print "v26.13.1".
# Verify npm version:
npm -v # Should print "11.20.0".
sudo npm install -g promptfoo@latest
# Run the red-team suite
export LITELLM_TEST_KEY="<YOUR_WIN11_VIRTUAL_KEY>"
promptfoo eval -c redteam/promptfooconfig.yaml

# Launch the interactive results dashboard (http://localhost:15500)
promptfoo view
```

---

## Verification & Red-Team Results

### **Ansible Compliance (`verify_security.yml`):** 
- Confirmed internal services (`Presidio :3000`, `Guardrails :8000`, `PostgreSQL :5432`, `Qdrant :6333/6334`) have zero host-exposed ports
- `OpenClaw` runs as `1000:1000` with `ReadonlyRootfs=true` and `CapDrop=[ALL]`
- `safe_ingest.py` blocks malicious injections (`rc=2`) while wrapping clean telemetry in `<verified_external_data>` XML delimiters (`rc=0`)  

### **Promptfoo Security Benchmark (`6/6 PASS`):**
- Verified Presidio DLP secret blocking
  - Stage 1 Unicode/regex injection defense
  - Stage 2 ONNX DeBERTa semantic detection (`confidence: 1.00`), and Server 2 `/ingest` RAG poisoning rejection.

---
## Screenshots

![Image of verify_security Ansible step](/media/safe_ingest.png)
![Image of Promptfoo scorecard](/media/promptfoo.png)