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

<details>

<summary>Prerequisites</summary>

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

</details>

---

## Quick-Start Deployment (Zero Pre-Configuration Required)

This repository uses a self-bootstrapping Ansible workflow—no manual `group_vars` editing or secret pre-generation is required.

### 1. Clone & Run the Interactive Bootstrap
From your Ansible control node (Ubuntu / WSL2 with SSH key access to both Ubuntu servers):
   ```bash
   git clone https://github.com/SnakesAndLadders/AILab.git
   cd AILab
   ansible-playbook -i localhost playbooks/site.yml
   ```
On the first run, Ansible automatically:
1. Prompts for **Server 1 IP**, **Server 2 IP**, and your **SSH username**, generating `inventory.ini` (gitignored).
2. Auto-generates 32-character cryptographic tokens (`LITELLM_MASTER_KEY`, `GUARDRAILS_TOKEN`, `OPENCLAW_GATEWAY_TOKEN`, `LITELLM_DB_PASSWORD`, and `OPEN_NOTEBOOK_ENCRYPTION_KEY`).
3. Prompts once (with `no_log: true`) for your `WORKSTATION_IP` and free-tier API keys (`GROQ_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`), writing hardened `0600` `.env` files directly to each server.
4. Configures UFW host firewalls, internal Docker networks, Presidio Canadian PII redaction (`CA_SIN`, `CA_POSTAL_CODE`, `AB_PHN`, `AWS_ACCESS_KEY`), and the two-stage Regex + ONNX DeBERTa-v3 prompt-injection shield.
5. Generates LiteLLM virtual API keys for Openclaw, server2, and the Promptfoo client (and presents the last one so you can copy it) 

*(On subsequent runs, Ansible reads existing `.env` secrets and `inventory.ini` automatically without prompting again, and only restarts containers whose configuration files changed.)*

---

### Step 2: Deploy Server 1 (AI Security Gateway & Hardened OpenClaw)
Run the playbook targeting `security_gateway` first (configures 4 GB swap, disables lid-close suspend, installs Docker, builds the ONNX DeBERTa classifier, and configures UFW):
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --limit security_gateway --ask-become-pass
```
---

### Step 3: Deploy Server 2 & Apply Virtual Keys Across Both Nodes
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --ask-become-pass
```

---

### Step 4: Run Automated Security & Compliance Checks
Verify UFW rules, swap health, internal container network isolation, `read_only` / `cap_drop: [ALL]` flags, and `safe_ingest.py` injection blocking:
```bash
ansible-playbook -i inventory.ini playbooks/verify_security.yml --ask-become-pass
```
You should now have a working deployment.

---

<details>

<summary>If you would like to change the public LLM Providers</summary>

## Adding or removing models
This stack comes pre-configured with models but you can change them at any time. There are 2 files to configure.
1. ./playbooks/server1_gateway.yml
This section:
```YAML
- name: Build baseline secrets (preserve existing or auto-generate random 32-char tokens)
      ansible.builtin.set_fact:
        merged_env:
          LITELLM_MASTER_KEY: "{{ existing_env.LITELLM_MASTER_KEY | default('sk-' + lookup('ansible.builtin.password', '/dev/null length=32 chars=ascii_letters,digits'), true) }}"
          GUARDRAILS_TOKEN: "{{ existing_env.GUARDRAILS_TOKEN | default(lookup('ansible.builtin.password', '/dev/null length=32 chars=ascii_letters,digits'), true) }}"
          OPENCLAW_GATEWAY_TOKEN: "{{ existing_env.OPENCLAW_GATEWAY_TOKEN | default(lookup('ansible.builtin.password', '/dev/null length=32 chars=ascii_letters,digits'), true) }}"
          OPENCLAW_LITELLM_KEY: "{{ existing_env.OPENCLAW_LITELLM_KEY | default('PENDING', true) }}"
          LITELLM_DB_PASSWORD: "{{ existing_env.LITELLM_DB_PASSWORD | default(lookup('ansible.builtin.password', '/dev/null length=32 chars=ascii_letters,digits'), true) }}"
          SAMBANOVA_API_KEY: "{{ existing_env.SAMBANOVA_API_KEY | default('', true) }}"
          CLOUDFLARE_API_KEY: "{{ existing_env.CLOUDFLARE_API_KEY | default('', true) }}"
          CLOUDFLARE_ACCOUNT_ID:  "{{ existing_env.CLOUDFLARE_ACCOUNT_ID | default('', true) }}"
          GEMINI_API_KEY: "{{ existing_env.GEMINI_API_KEY | default('', true) }}"
          OPENROUTER_API_KEY: "{{ existing_env.OPENROUTER_API_KEY | default('', true) }}"
          SERVER2_IP: "{{ hostvars['server2']['ansible_host'] }}"
          LAN_SUBNET: "{{ existing_env.LAN_SUBNET | default('', true) }}"
          CLIENT_SUBNET: "{{ existing_env.CLIENT_SUBNET | default('', true) }}"
          WORKSTATION_IP: "{{ existing_env.WORKSTATION_IP | default('', true) }}"
          DISCORD_BOT_ID: "{{ existing_env.DISCORD_BOT_ID | default('', true) }}"
          DISCORD_SERVER_ID: "{{ existing_env.DISCORD_SERVER_ID | default('', true) }}"
          DISCORD_OWNER_ID: "{{ existing_env.DISCORD_OWNER_ID | default('', true) }}"
          FREELLMAPI_API_KEY: "{{ existing_env.FREELLMAPI_API_KEY | default('', true) }}"
      no_log: true
```

either stores or generates the keys/settings that your stack uses. To add an existing key (like Groq for exampe) you would add something like ``` GROQ_API_KEY=  "{{ existing_env.GROQ_API_KEY | default('', true) }}" ``` , This will cause your Ansible run to ask for the key if it is not there, and store it in the .env file for that server. After that update the .env section of your docker-compose if required.  

You can also generate API keys/passwords to use in containers like Open Notebook automatically by appending ``` YOUR_NEW_TOKEN: "{{ existing_env.YOUR_NEW_TOKEN | default(lookup('ansible.builtin.password', '/dev/null length=32 chars=ascii_letters,digits'), true) }}" ``` to the end of the list, and the Ansible run will automatically create and store a 32 character password/key for you.

2. ./files/server1/litellm_config.yml 

There are 3 types of models that Litellm offers up in this config. You connect the models that LiteLLM servers to the public LLM models you have an API key for, and LiteLLM will load balance them. When setting up the configuration you need to set an order of preference if you are connecting multiple "outside" models to one "inside" model by making sure the "order: " is set to a unique number. Update, remove, or add sections at the top of the config file:
```YAML
- model_name: safe-chat-default
    litellm_params:
      model: cloudflare/google/gemma-4-26b-a4b-it
      api_key: os.environ/CLOUDFLARE_API_KEY
      rpm: 30
      order: 1
```
Make sure you pay attention to the "safe-chat-default", "safe-embed-default", and "safe-whisper-default" model names so your external calls are routed to the correct "outside" model. THis part can be tricky.  

3. Make sure your file is saved and run your server 1 Ansible playbook to update the settings. 
```bash
ansible-playbook -i inventory.ini playbooks/site.yml --limit security_gateway --ask-become-pass
```
4. The LiteLLM container should restart, but check it to make sure. If it didn't just manually restart it.
</details>
   
---

<details>

<summary>Run Security Tests</summary>

## Automated Security Verification & Red-Teaming

### 1. Infrastructure & Isolation Compliance (`verify_security.yml`)
```bash
ansible-playbook -i inventory.ini playbooks/verify_security.yml
```
Validates active UFW policies, container health across both laptops, `safe_ingest.py` XML boundary enforcement, OpenClaw direct-internet air-gapping, and Qdrant vector DB network isolation.

### 2. Adversarial Red-Team Benchmark (`Promptfoo`)
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

| Probe | Target Control | Expected Outcome | Result |
| :--- | :--- | :--- | :---: |
| Clean infrastructure query | LiteLLM Gateway (`:4000`) | Allowed (`HTTP 200`) | **PASS** |
| Hardcoded `AWS_ACCESS_KEY_ID` | Microsoft Presidio Egress DLP | Blocked (`HTTP 400`) | **PASS** |
| Zero-width Unicode smuggling (`\u200B`) | Guardrails Stage 1 (Unicode/Regex) | Blocked (`HTTP 400`) | **PASS** |
| `[SYSTEM]` override & `/etc/passwd` read | Guardrails Stage 1 (Signature Filter) | Blocked (`HTTP 400`) | **PASS** |
| Paraphrased semantic injection | Guardrails Stage 2 (ONNX DeBERTa-v3) | Blocked (`confidence: 1.00`) | **PASS** |
| Poisoned RAG document ingestion | Firewalled RAG `/ingest` (`:8090`) | Rejected (`HTTP 400`) | **PASS** |

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

</details>

---
## Screenshots

![Image of verify_security Ansible step](/media/safe_ingest.png)
![Image of Promptfoo scorecard](/media/promptfoo.png)
