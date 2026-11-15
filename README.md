# Dual-Server Zero-Trust AI Security & Firewalled RAG Gateway

An enterprise-inspired, self-hosted AI security architecture designed to enforce **bi-directional LLM guardrails**, **PII/secret egress redaction**, **RAG poisoning defense**, and **autonomous agent sandboxing** across heterogeneous legacy compute hardware.

## Architecture Overview

This lab separates security enforcement from application workloads across two bare-metal servers without GPUs:

* **Server 1 - AI Security Gateway (`IBM System x3550 M2` | Dual Xeon E5520 | 36 GB RAM):**
  * **LiteLLM Proxy (Port `4000`):** Unified OpenAI-compatible control plane issuing scoped virtual API keys, per-client RPM rate limits, and automatic fallback routing across free-tier LLM and embedding providers.
  * **Microsoft Presidio (`pre_call` Egress Hook):** Scans outgoing prompts and code snippets for PII (`US_SSN`, `CREDIT_CARD`, `EMAIL_ADDRESS`) and hardcoded secrets (`AWS_ACCESS_KEY`), masking or blocking sensitive data before it leaves the local network.
  * **Guardrails AI (`pre_call` & Standalone Validation):** Custom CPU-safe Python validator (`nehalem-safe-shield`) blocking direct/indirect prompt injections, agent command hijacking, homoglyph attacks, and zero-width Unicode smuggling.
  * **Network Isolation:** Presidio and Guardrails AI reside on an `internal: true` Docker bridge (`secure_egress`), making it impossible for LAN clients to bypass the LiteLLM control plane.

* **Server 2 - Workloads & Firewalled RAG (`HP ProLiant DL160 G6` | Dual Xeon E5520 | 36 GB RAM):**
  * **Secure RAG API (Port `8090`):** FastAPI ingestion and retrieval gateway that validates all incoming documents against Server 1's Guardrails AI shield *before* generating embeddings or writing vectors.
  * **Qdrant Vector Database:** Isolated inside an `internal: true` Docker network (`rag_internal`) so untrusted pipelines cannot inject poisoned embeddings directly.
  * **Open Notebook & Speakr:** Research and `int8` CPU Whisper transcription workloads routed strictly through Server 1's egress proxy.

* **Client Tier:**
  * **Windows 11 Workstation:** VSCode + OpenCode routed to LiteLLM (`:4000`) and Secure RAG (`:8090`) using a scoped developer virtual key.
  * **Ubuntu 26.04 Desktop:** Physically isolated host running the **OpenClaw** autonomous agent under a strict rate-limited virtual key and pre-screened ingress pipelines.

---

## Threat Model & Mitigations

| Threat Vector | Attack Scenario | Control Implemented |
| :--- | :--- | :--- |
| **Sensitive Data Egress** | Developer pastes `.env` secrets or customer PII into coding assistant | Presidio `pre_call` hook blocks SSNs/AWS keys and masks emails/cards before upstream API calls |
| **Indirect Prompt Injection** | Scraped webpage or webhook contains hidden `[SYSTEM]` instructions targeting OpenClaw | Standalone `/guardrails/apply_guardrail` inspection + zero-width Unicode stripping |
| **RAG Knowledge Poisoning** | Malicious document injected into vector DB to hijack future agent queries | `/ingest` endpoint enforces Guardrails AI validation prior to Qdrant vector upsert |
| **Runaway Agent / Quota Exhaustion** | Autonomous agent enters an infinite tool-calling loop | LiteLLM virtual keys enforce per-client `rpm_limit` isolation |
| **Host Lateral Movement** | Compromised agent attempts to access primary workstation SSH keys or repos | OpenClaw isolated on dedicated Ubuntu 26.04 host with UFW egress restrictions |

---

## Automated Red-Teaming & Verification

Security controls are continuously validated using **Promptfoo** (`promptfooconfig.yaml`):
1. **Egress DLP Tests:** Confirms `403` blocks on SSNs/AWS keys and verifies upstream models never receive unmasked emails or card numbers.
2. **Ingress Injection Tests:** Confirms detection of instruction overrides, bash exfiltration payloads (`cat ~/.ssh/id_rsa`), and `\u200B` zero-width character smuggling.
3. **RAG Poisoning Tests:** Confirms malicious documents are rejected at `:8090/ingest` while clean SOP documents are embedded and retrievable via `:8090/query`.

## Deployment & Verification Guide

### Prerequisites
* **Control Node:** Linux host or Windows 11 with WSL2 (Ubuntu) running `ansible` (`>= 2.15`) and SSH key-based access to all three target nodes.
* **Target Nodes:**
  * **Server 1 (`192.168.1.10`):** Ubuntu Server (IBM System x3550 M2) — AI Security Gateway
  * **Server 2 (`192.168.1.11`):** Ubuntu Server (HP ProLiant DL160 G6) — RAG & App Workloads
  * **OpenClaw Host (`192.168.1.12`):** Ubuntu 26.04 Desktop — Isolated Agent Host
* **API Keys:** Free-tier keys from Groq, Google AI Studio (Gemini), OpenRouter, or Mistral.

---

### Step 1: Configure Inventory & Secrets
1. Clone this repository onto your Ansible control node:
   ```bash
   git clone https://github.com/SnakesAndLadders/AILab.git
   cd AILab
   ```
2. Update `inventory.ini` with your static LAN IP addresses and SSH usernames.
3. Edit `group_vars/all.yml` to add your upstream free-tier API keys and a strong `litellm_master_key`. *(Optional: Encrypt the file using `ansible-vault encrypt group_vars/all.yml`.)*
4. Verify Ansible connectivity across all three nodes:
   ```bash
   ansible all -i inventory.ini -m ping
   ```

---

### Step 2: Deploy Server 1 (AI Security Gateway)
Deploy LiteLLM Proxy, Microsoft Presidio, Guardrails AI, and UFW rules on Server 1 first so you can generate scoped virtual keys for downstream hosts:
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --limit security_gateway --ask-become-pass
```

---

### Step 3: Issue Scoped Virtual API Keys
Generate isolated, rate-limited virtual keys via LiteLLM's `/key/generate` endpoint so no single client can exhaust free-tier quotas or bypass governance:

1. **Generate Key for Server 2 (RAG Embeddings & Workloads):**
   ```bash
   curl -X POST 'http://192.168.1' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "server2-rag-apps", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 30}'
   ```
2. **Generate Key for Ubuntu 26.04 OpenClaw Host (Strict RPM Cap):**
   ```bash
   curl -X POST 'http://192.168.1' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "ubuntu-openclaw", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 10}'
   ```
3. **Generate Key for Windows 11 Workstation (OpenCode & Promptfoo):**
   ```bash
   curl -X POST 'http://192.168.1' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "win11-opencode", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 30}'
   ```
4. Paste the generated keys for `server2_litellm_key` and `openclaw_litellm_key` into `group_vars/all.yml`.

---

### Step 4: Deploy Server 2 & Harden the OpenClaw Host
Run the full playbook to stand up Qdrant, the Secure RAG API, Open Notebook, and Speakr on Server 2, while locking down the Ubuntu 26.04 OpenClaw host (`openclaw-svc` account, `systemd` sandboxing, UFW egress rules, and `safe_ingest.py`):
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --ask-become-pass
```

---

### Step 5: Run Automated Security & Compliance Checks
Execute the verification playbook to confirm UFW rules are active, internal containers (`Presidio`, `Guardrails AI`, `Qdrant`) have zero exposed host ports, lateral movement from OpenClaw is blocked, and `safe_ingest.py` rejects prompt injections:
```bash
ansible-playbook -i inventory.ini playbooks/verify_security.yml --ask-become-pass
```

---

### Step 6: Execute Promptfoo Red-Team Evaluation (Windows 11)
From your Windows 11 workstation, run the automated red-team suite against both the LiteLLM Gateway (`:4000`) and Secure RAG Ingestion API (`:8090`):
```powershell
npm install -g promptfoo
\$env:LITELLM_TEST_KEY="<YOUR_WIN11_VIRTUAL_KEY>"
promptfoo eval -c redteam/promptfooconfig.yaml
promptfoo view
```


## Engineering Lessons Learned (Legacy Hardware Constraints)
Deploying modern AI security tooling on 2009 Intel Xeon E5520 (Nehalem) CPUs without AVX/AVX2 instructions required avoiding AVX2-compiled PyTorch/ONNX wheels. Instead, this architecture pairs compiled Rust/Go binaries (**Qdrant**) with deterministic/regex/NFKC Unicode validators (**Guardrails AI** + **Presidio**) and offloads heavy transformer inference and embeddings to rate-limited cloud endpoints behind a strict local DLP perimeter.

```mermaid
flowchart LR
    %% Styling
    classDef client fill:#f3f6fa,stroke:#2b579a,stroke-width:2px,color:#111
    classDef gateway fill:#eef7f2,stroke:#1e7e34,stroke-width:2px,color:#111
    classDef isolated fill:#fff5f5,stroke:#c53030,stroke-width:2px,stroke-dasharray: 5 5,color:#111
    classDef external fill:#f8f9fa,stroke:#4a5568,stroke-width:2px,color:#111

    %% Client Tier
    subgraph CLIENTS["Client Tier & External Data"]
        direction TB
        subgraph WIN11["Windows 11 Workstation (192.168.1.20)"]
            OPENCODE["VSCode + OpenCode"]
            PROMPTFOO["Promptfoo Red-Team Suite"]
        end

        EXT_DATA["External Untrusted Data<br/>(Webhooks / Scraped Pages)"]

        subgraph UBUNTU["Ubuntu 26.04 Desktop (192.168.1.12)<br/>[UFW Egress Lockdown]"]
            SAFE_INGEST["safe_ingest.py<br/>(Air-Lock Wrapper | openclaw-svc)"]
            OPENCLAW["OpenClaw Agent<br/>(Systemd Sandboxed)"]
            SAFE_INGEST -->|"Bounded XML Text"| OPENCLAW
        end
    end

    %% Server 1
    subgraph SERVER1["Server 1: IBM System x3550 M2 (192.168.1.10) - AI Security Gateway"]
        direction TB
        subgraph S1_LAN["Network Zone 1: lan_ingress"]
            LITELLM["LiteLLM Proxy (Port 4000)<br/>Virtual Keys & RPM Rate Limits"]
        end
        subgraph S1_SEC["Network Zone 2: secure_egress (Internal Only)"]
            PRESIDIO["Microsoft Presidio<br/>(pre_call PII & Secret Redaction)"]
            GUARDRAILS["Guardrails AI<br/>(nehalem-safe-shield: Injection & Unicode)"]
        end
        LITELLM <-->|"pre_call Scrubbing"| PRESIDIO
        LITELLM <-->|"pre_call & Standalone"| GUARDRAILS
    end

    %% Server 2
    subgraph SERVER2["Server 2: HP ProLiant DL160 G6 (192.168.1.11) - Workloads & Firewalled RAG"]
        direction TB
        subgraph S2_LAN["Network Zone 1: lan_net"]
            RAG_API["Secure RAG API (Port 8090)"]
            NOTEBOOK["Open Notebook (Port 8502)"]
            SPEAKR["Speakr CPU Whisper (Port 8899)"]
        end
        subgraph S2_RAG["Network Zone 2: rag_internal (Internal Only)"]
            QDRANT["Qdrant Vector DB (Port 6333)"]
        end
        RAG_API <-->|"Store/Retrieve Clean Vectors"| QDRANT
    end

    %% External Cloud
    CLOUD["Public Free-Tier LLMs & Embeddings<br/>(Groq, Gemini, OpenRouter, Mistral)"]

    %% Traffic Flows
    OPENCODE -->|"Sanitized Prompts (:4000/v1)"| LITELLM
    OPENCODE -->|"RAG Queries (:8090/query)"| RAG_API
    PROMPTFOO -.->|"Red-Team Probes (:4000 & :8090)"| LITELLM
    PROMPTFOO -.->|"Poisoning Tests (:8090/ingest)"| RAG_API

    EXT_DATA -->|"Untrusted Input"| SAFE_INGEST
    SAFE_INGEST -->|"Validate (:4000/apply_guardrail)"| LITELLM
    SAFE_INGEST -->|"Ingest Clean (:8090/ingest)"| RAG_API
    OPENCLAW -->|"Scoped Chat & RAG Queries"| LITELLM
    OPENCLAW -->|"Context Retrieval (:8090/query)"| RAG_API

    RAG_API -->|"Validate & Embed (:4000)"| LITELLM
    NOTEBOOK -->|"Egress Prompts (:4000/v1)"| LITELLM
    SPEAKR -->|"Egress Summaries (:4000/v1)"| LITELLM

    LITELLM -->|"Sanitized Prompts & Embeddings"| CLOUD

    %% Apply Classes
    class OPENCODE,PROMPTFOO,SAFE_INGEST,OPENCLAW client
    class LITELLM,RAG_API,NOTEBOOK,SPEAKR gateway
    class PRESIDIO,GUARDRAILS,QDRANT isolated
    class EXT_DATA,CLOUD external
```
