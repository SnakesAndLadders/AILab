# Dual-Server Zero-Trust AI Security & Firewalled RAG Gateway

An enterprise-inspired, self-hosted AI security architecture designed to enforce **bi-directional LLM guardrails**, **PII/secret egress redaction**, **RAG poisoning defense**, and **autonomous agent sandboxing** across heterogeneous legacy compute hardware.

## Architecture Overview

This lab repurposes two energy-efficient, AVX2-capable Kaby Lake laptops (~15W–30W TDP) with built-in battery backup as dedicated bare-metal security and RAG nodes, managed declaratively via Ansible:

* **Server 1 — AI Security Gateway (`Dell Latitude 7480` | Intel Core i5-7300U | 16 GB RAM):**
  * **LiteLLM Proxy (`2.5G` cap | Port `4000`):** Unified OpenAI-compatible control plane issuing scoped virtual API keys, per-client RPM rate limits, and automatic fallback routing across free-tier LLM and embedding providers.
  * **Microsoft Presidio (`3.5G` combined cap):** Scans outgoing prompts and code snippets (`pre_call`) for PII (`US_SSN`, `CREDIT_CARD`, `EMAIL_ADDRESS`) and hardcoded secrets (`AWS_ACCESS_KEY`), masking or blocking sensitive data before egress.
  * **Guardrails AI Two-Stage Hybrid Shield (`3.5G` cap):**
    * **Stage 1 (Deterministic Pre-Filter, `<1 ms`):** Strips and blocks zero-width Unicode smuggling (`\u200B`), normalizes homoglyphs (`NFKC`), and drops high-confidence shell-hijacking signatures before invoking neural inference.
    * **Stage 2 (Local ONNX DeBERTa-v3 Classifier, `~45 ms`):** Runs a pre-baked `optimum[onnxruntime]` export of `protectai/deberta-v3-base-prompt-injection-v2` on AVX2 CPU cores to catch paraphrased semantic injections that contain zero static regex keywords.

* **Server 2 — Workloads & Firewalled RAG (`Lenovo Ideapad 130-15IKB` | Intel Core i7-8550U 8-Thread | 12 GB RAM):**
  * **Secure RAG API (`1G` cap | Port `8090`):** FastAPI ingestion and retrieval gateway that validates incoming documents against Server 1's two-stage Guardrails AI shield *before* generating embeddings or writing vectors.
  * **Qdrant Vector Database (`2G` cap):** Isolated inside an `internal: true` Docker network (`rag_internal`) so untrusted pipelines cannot inject poisoned embeddings directly.
  * **Open Notebook (`2.5G` cap | Port `8502`) & Speakr (`3G` cap | Port `8899`):** Research and 8-thread `int8` CPU Whisper transcription workloads routed strictly through Server 1's egress proxy.


* **Client Tier:**
  * **Windows 11 Workstation:** VSCode + OpenCode routed to LiteLLM (`:4000`) and Secure RAG (`:8090`) using a scoped developer virtual key.
  * **Ubuntu 26.04 Desktop:** Physically isolated host running the **OpenClaw** autonomous agent under a strict rate-limited virtual key and pre-screened ingress pipelines.

---

## Threat Model & Mitigations

| Threat Vector | Attack Scenario | Control Implemented |
| :--- | :--- | :--- |
| **Sensitive Data Egress** | Developer pastes `.env` secrets or customer PII into coding assistant | Presidio `pre_call` hook blocks SSNs/AWS keys and masks emails/cards before upstream API calls |
| **Obfuscated & Signature Injections** | Scraped page hides `[SYSTEM]` commands or `\u200B` zero-width smuggling | Guardrails Stage 1 normalizes Unicode (`NFKC`) and blocks known hijacking signatures in `<1 ms` |
| **Paraphrased Semantic Injections** | Attacker uses polite, synonym-heavy phrasing to bypass static regex rules | Guardrails Stage 2 local ONNX `deberta-v3` classifier scores semantic intent (`threshold >= 0.85`) |
| **RAG Knowledge Poisoning** | Malicious document injected into vector DB to hijack future agent queries | `/ingest` endpoint enforces two-stage Guardrails AI validation prior to Qdrant vector upsert |
| **Runaway Agent / Quota Exhaustion** | Autonomous agent enters an infinite tool-calling loop | LiteLLM virtual keys enforce per-client `rpm_limit` isolation |
| **Host Lateral Movement** | Compromised agent attempts to access primary workstation SSH keys or repos | OpenClaw isolated on dedicated Ubuntu 26.04 host with `systemd` sandboxing & UFW egress blocks |

---

## Automated Red-Teaming & Verification

Security controls are continuously validated using **Promptfoo** (`promptfooconfig.yaml`):
1. **Egress DLP Tests:** Confirms `403` blocks on SSNs/AWS keys and verifies upstream models never receive unmasked emails or card numbers.
2. **Ingress Injection Tests:** Confirms detection of instruction overrides, bash exfiltration payloads (`cat ~/.ssh/id_rsa`), and `\u200B` zero-width character smuggling.
3. **RAG Poisoning Tests:** Confirms malicious documents are rejected at `:8090/ingest` while clean SOP documents are embedded and retrievable via `:8090/query`.

## Deployment & Verification Guide

### Prerequisites
* **Control Node:** Linux host or Windows 11 with WSL2 (Ubuntu) running `ansible` (`>= 2.15`) and SSH key-based access to all three target nodes. IPs are just placeholders, use whatever you like.
* **Target Nodes:**
  * **Server 1 (`192.168.1.10`):** - AI Security Gateway
  * **Server 2 (`192.168.1.11`):** - RAG & App Workloads
  * **OpenClaw Host (`192.168.1.12`):** Ubuntu 26.04 Desktop — Isolated Agent Host
* **API Keys:** Free-tier keys from Groq, Google AI Studio (Gemini), OpenRouter, or Mistral.

### Installing Ansible (Control Node Setup)

Ansible must run on a Linux control node. If your primary workstation is **Windows 11**, install **WSL2 (Ubuntu)** first, then install Ansible inside the Ubuntu terminal.

#### 1. Windows 11: Install WSL2 & Ubuntu (Skip if already on Linux)
Open **PowerShell as Administrator** and run:
```powershell
wsl --install -d Ubuntu
```
Reboot your computer if prompted, launch **Ubuntu** from the Start Menu, and create your Linux username and password.

#### 2. Install Ansible & Required Collections (Ubuntu / WSL2)
Inside your Ubuntu terminal, install Ansible using the official PPA and add the `community.general` collection (required for managing UFW firewall rules):

```bash
sudo apt update
sudo apt install -y software-properties-common sshpass
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install -y ansible

# Install community.general collection for the UFW firewall module
ansible-galaxy collection install community.general
```

#### 3. Verify Installation & Configure SSH Keys
Confirm Ansible is installed and generate an SSH keypair so Ansible can connect to Server 1, Server 2, and your OpenClaw host without password prompts:

```bash
ansible --version

# Generate an Ed25519 SSH key (press Enter to accept default path)
ssh-keygen -t ed25519 -C "ansible-control-node"

# Copy your public key to all three target hosts
ssh-copy-id ubuntu@192.168.1.10
ssh-copy-id ubuntu@192.168.1.11
ssh-copy-id ubuntu@192.168.1.12
```

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
   curl -X POST 'http://[Security Gateway IP]' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "server2-rag-apps", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 30}'
   ```
2. **Generate Key for Ubuntu 26.04 OpenClaw Host (Strict RPM Cap):**
   ```bash
   curl -X POST 'http://[Security Gateway IP]' \
     -H 'Authorization: Bearer <YOUR_LITELLM_MASTER_KEY>' \
     -H 'Content-Type: application/json' \
     -d '{"key_alias": "ubuntu-openclaw", "models": ["safe-chat-default", "safe-embed-default"], "rpm_limit": 10}'
   ```
3. **Generate Key for Windows 11 Workstation (OpenCode & Promptfoo):**
   ```bash
   curl -X POST 'http://[Security Gateway IP]' \
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
### Windows 11 Control Node
Run the automated red-team suite against both the LiteLLM Gateway (`:4000`) and Secure RAG Ingestion API (`:8090`):
```powershell
npm install -g promptfoo
\$env:LITELLM_TEST_KEY="<YOUR_WIN11_VIRTUAL_KEY>"
promptfoo eval -c redteam/promptfooconfig.yaml
promptfoo view
```
### Linux or WSL2 Control Node 
allows you to execute your automated red-team suite directly alongside your Ansible playbooks.

#### 1. Install Node.js (v20+) & Promptfoo
If Node.js is not already installed on your control node, install the NodeSource LTS release and Promptfoo globally:

```bash
# Install Node.js 20.x LTS
curl -fsSL https://nodesource.com | sudo -E bash -
sudo apt-get install -y nodejs

# Install Promptfoo CLI
sudo npm install -g promptfoo

# Verify installation
promptfoo --version
```

#### 2. Run the Automated Security Benchmark
Export your Windows 11 / Control Node LiteLLM virtual key and run the evaluation against both Server 1 (`:4000`) and Server 2 (`:8090`):

```bash
cd ~/ai-security-ansible
export LITELLM_TEST_KEY="<YOUR_WIN11_VIRTUAL_KEY>"

# Execute all Egress DLP, Ingress Injection, and RAG Poisoning tests
promptfoo eval -c redteam/promptfooconfig.yaml
```

#### 3. Inspect the Results Dashboard
Launch the local web viewer to inspect pass/fail assertions, latency metrics, and masked payloads:

```bash
promptfoo view
```
> [!TIP] 
> *(If running inside WSL2 on Windows 11, open the `http://localhost:15500` link printed in your terminal directly in your Windows browser. If running on a headless remote Linux server, forward the port via SSH using `ssh -L 15500:localhost:15500 user@<CONTROL_NODE_IP>`.)*

## Engineering Lessons Learned & Architectural Trade-Offs

Building an enterprise-style AI security perimeter on repurposed laptop hardware (`16 GB` + `12 GB` RAM, CPU-only) surfaced several practical engineering lessons that directly mirror real-world production constraints:

1. **CPU Instruction Sets Dictate Local ML Feasibility (Nehalem vs. Kaby Lake AVX2)**
   * Early architectural scoping on legacy 2009 Xeon E5520 (Nehalem) servers revealed that modern PyTorch and ONNX wheels trigger `Illegal instruction` crashes on CPUs lacking AVX/AVX2 extensions.
   * Moving the stack to 7th/8th Gen Intel Kaby Lake laptops (`i5-7300U` & `i7-8550U`) unlocked **AVX2 vector instructions**, making it possible to run a pre-baked ONNX `deberta-v3` prompt-injection classifier (`~45 ms` inference) and `int8` Whisper transcription locally without a discrete GPU.

2. **Two-Stage Hybrid Guardrails Balance Latency and Semantic Coverage**
   * Running a transformer classifier on every single request adds unnecessary CPU load for obvious attacks, while regex-only filters fail against paraphrased jailbreaks.
   * Chaining a **Stage 1 deterministic pre-filter** (`<1 ms` Unicode `NFKC` normalization, zero-width character stripping, and high-confidence command signatures) ahead of a **Stage 2 ONNX DeBERTa classifier** drops trivial attacks immediately while catching novel semantic injections.

3. **Security vs. Autonomy in Read-Only Agent Containers (`read_only: true`)**
   * Consolidating the **OpenClaw** autonomous agent onto Server 1 alongside the security gateway traded physical host separation for hardware efficiency.
   * To preserve zero-trust boundaries without crashing the agent on `Read-only file system` errors, `read_only: true` and `cap_drop: [ALL]` were paired with **UID-scoped `tmpfs` scratch mounts** (`/tmp`, `/home/node/.cache`, `/home/node/.npm`) and isolated bridge networks (`openclaw_net` separated from `secure_egress`), while explicitly withholding `/var/run/docker.sock`.

4. **Memory Budgeting & Swap Cushions Prevent OOM Kills on Constrained Nodes**
   * Running NLP models (Microsoft Presidio + ONNX DeBERTa) alongside a vector database (Qdrant) and audio transcription (Speakr) within `16 GB` and `12 GB` RAM envelopes requires strict Docker `deploy.resources.limits.memory` caps and a `4 GB` swapfile cushion so transient traffic spikes degrade gracefully rather than triggering Linux OOM kills.

5. **Infrastructure-as-Code & Automated Red-Teaming Turn Labs into Auditable Systems**
   * Automating host hardening, lid-close keepalive tuning, UFW egress lockdowns, and container builds via **Ansible** ensures repeatable deployments.
   * Pairing post-deployment compliance checks (`verify_security.yml`) with **Promptfoo** regression suites turns security controls (PII masking, secret blocking, and RAG poisoning defense) into measurable, verifiable telemetry rather than assumptions.


``` mermaid 
flowchart LR
    %% Styling
    classDef client fill:#f3f6fa,stroke:#2b579a,stroke-width:2px,color:#111
    classDef gateway fill:#eef7f2,stroke:#1e7e34,stroke-width:2px,color:#111
    classDef isolated fill:#fff5f5,stroke:#c53030,stroke-width:2px,stroke-dasharray: 5 5,color:#111
    classDef external fill:#f8f9fa,stroke:#4a5568,stroke-width:2px,color:#111

    %% Client Tier
    subgraph CLIENTS["Workstation & External Data"]
        direction TB
        subgraph WIN11["Windows 11 Workstation (192.168.1.20)"]
            OPENCODE["VSCode + OpenCode"]
            PROMPTFOO["Promptfoo Red-Team Suite<br/>(Regex + Semantic ML Probes)"]
        end
        EXT_DATA["External Untrusted Data<br/>(Webhooks / Scraped Pages)"]
    end

    %% Server 1 (Dell Latitude 7480)
    subgraph SERVER1["Server 1: Dell Latitude 7480 (192.168.1.10) - i5-7300U | 16GB RAM"]
        direction TB
        subgraph S1_LAN["Zone 1: lan_ingress"]
            LITELLM["LiteLLM Proxy (Port 4000)<br/>Virtual Keys & RPM Rate Limits"]
        end
        subgraph S1_SEC["Zone 2: secure_egress (Internal Only)"]
            PRESIDIO["Microsoft Presidio<br/>(pre_call PII & Secret Redaction)"]
            GUARDRAILS["Guardrails AI Hybrid Shield<br/>Stage 1: Unicode & Regex (<1ms)<br/>Stage 2: ONNX DeBERTa-v3 ML (~45ms)"]
        end
        subgraph S1_OC["Zone 3: openclaw_net (Hardened Container: cap_drop ALL, read_only)"]
            SAFE_INGEST["safe_ingest.py (Air-Lock)"]
            OPENCLAW["OpenClaw Agent (Port 18789)"]
            SAFE_INGEST -->|"Bounded XML Text"| OPENCLAW
        end
        LITELLM <-->|"pre_call Scrubbing"| PRESIDIO
        LITELLM <-->|"pre_call & Standalone"| GUARDRAILS
        SAFE_INGEST -->|"Two-Stage Scan (:4000)"| LITELLM
        OPENCLAW -->|"Scoped Chat (:4000/v1)"| LITELLM
    end

    %% Server 2 (Lenovo Ideapad 130-15IKB)
    subgraph SERVER2["Server 2: Lenovo Ideapad 130-15IKB (192.168.1.11) - i7-8550U | 12GB RAM"]
        direction TB
        subgraph S2_LAN["Zone 1: lan_net"]
            RAG_API["Secure RAG API (Port 8090)"]
            NOTEBOOK["Open Notebook (Port 8502)"]
            SPEAKR["Speakr Whisper int8 (Port 8899)"]
        end
        subgraph S2_RAG["Zone 2: rag_internal (Internal Only)"]
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
    SAFE_INGEST -->|"Ingest Clean (:8090/ingest)"| RAG_API
    OPENCLAW -->|"Context Retrieval (:8090/query)"| RAG_API

    RAG_API -->|"Validate & Embed (:4000)"| LITELLM
    NOTEBOOK -->|"Egress Prompts (:4000/v1)"| LITELLM
    SPEAKR -->|"Egress Summaries (:4000/v1)"| LITELLM

    LITELLM -->|"Sanitized Prompts & Embeddings"| CLOUD

    %% Apply Classes
    class OPENCODE,PROMPTFOO client
    class LITELLM,RAG_API,NOTEBOOK,SPEAKR gateway
    class PRESIDIO,GUARDRAILS,QDRANT,SAFE_INGEST,OPENCLAW isolated
    class EXT_DATA,CLOUD external
```