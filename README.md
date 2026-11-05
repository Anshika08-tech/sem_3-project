# CampusVoice: Tamper-Evident Anonymous Grievance Tracker

> **One-Line Description:**
> *Students file anonymous grievances and track them with a receipt token; hash-chained audit logs and auto-escalation stop complaints being buried or edited.*

---

## 📌 Project Overview
**CampusVoice** is a privacy-first, cryptographically auditable grievance tracking platform designed for university campuses. It addresses two major problems faced by students:
1. **Fear of Retaliation / Loss of Anonymity:** Students hesitate to report issues such as hostel infrastructure failures, mess food hygiene, broken lab equipment, faculty misconduct, or ragging due to fear of being identified.
2. **Lack of Accountability / Quiet Dismissal:** Complaints submitted through suggestion boxes or emails are often ignored, delayed past deadlines, or quietly modified or deleted without student knowledge.

CampusVoice solves this by issuing high-entropy cryptographic receipt tokens (`CV-CAT-XXXX-YEAR`), enforcing automated time-bound SLA escalations across departmental hierarchies, and recording every event in a **tamper-evident SHA-256 hash-chained audit ledger**.

---

## 🚀 How to Run the Project
This project is built using zero-dependency, standard web technologies (HTML5, Modern CSS, Web Crypto API, Vanilla JS).

### Option 1: Direct Browser Launch (Easiest)
Simply double-click `index.html` or open it in any modern browser (Google Chrome, Apple Safari, Microsoft Edge, Mozilla Firefox).

### Option 2: Local HTTP Server (Python)
If you prefer running a local development server:
```bash
# In the project directory:
python3 -m http.server 8080
```
Then navigate to: `http://localhost:8080`

---

## 🌟 Core Features & Implementation

| Feature | Description | Implementation Details |
| :--- | :--- | :--- |
| **1. Anonymous Filing & Receipt Tokens** | Students file grievances with zero PII stored. Upon submission, a unique cryptographic receipt token is generated. | Uses high-entropy Web Crypto random values. No IP, email, or student identity is stored in state. |
| **2. Dynamic SLA Routing** | Directs grievances to designated authorities with predefined response windows. | Configured per category: Hostel (48h), Mess (24h), Labs (48h), Faculty (72h), Anti-Ragging (12h). |
| **3. Automated SLA Escalation Engine** | Background scheduler detects expired SLA deadlines and elevates cases up the hierarchy. | Automatically escalates from Tier 1 (e.g., Warden) to Tier 2 (Chief Warden) and Tier 3 (Dean of Students), logging audit records. |
| **4. Tamper-Evident Audit Ledger** | Every filing, status change, escalation, and resolution is permanently chained via SHA-256 hashes. | `hash = SHA256(index + gid + action + actor + detail + timestamp + prev_hash)`. Includes live verification and simulated attack testing. |
| **5. Evidence Upload (Azure Blob Simulation)** | Attach photos and PDFs to complaints. | Simulated Azure Blob Storage container with server-side AES-256 encryption metadata, time-limited SAS tokens, and Defender scan status. |
| **6. Executive Analytics & Hotspots** | Real-time administrative dashboard tracking campus problem areas and response metrics. | Live KPI cards (Active, Overdue, Escalated, Avg Resolution Time, SLA Compliance) and location hotspot distributions. |

---

## 🎬 Step-by-Step Viva Demonstration Guide

Use this sequence to deliver a high-scoring project presentation:

### Step 1: File an Anonymous Grievance (Student Role)
1. Select the **Student** persona from the top navigation.
2. On the **File Anonymous Grievance** tab, click one of the quick viva presets (e.g., `⚡ Hostel Water Leak` or `⚡ Mess Food Hygiene`).
3. Notice the **Auto-Routing Preview** showing the Tier 1 authority, SLA target, and escalation path.
4. Click **Submit Anonymous Grievance**.
5. A receipt modal appears with a unique token (e.g., `CV-HOS-8F2B-2026`). Click **Copy** and then **Track Progress Now**.

### Step 2: Track Progress & Live SLA Countdown (Student Role)
1. In the **Track by Receipt Token** tab, view the live timeline showing the filing timestamp and initial SLA countdown.
2. Click on the attached evidence photo or PDF to open the **Azure Blob Storage Inspector Modal**.
3. Point out that the student can add anonymous follow-up clarifications without compromising privacy.

### Step 3: Demonstrate Automated SLA Escalation (Time Travel Simulator)
1. Point to the **Simulated Campus Clock** ribbon at the top of the screen.
2. Click **+24 Hours** or **+72 Hours** to advance simulated time.
3. Observe how the SLA countdown breaches its deadline, triggering the auto-escalation daemon.
4. The grievance status automatically updates to **Escalated**, shifts to Tier 2 (e.g., Chief Warden), and logs an immutable audit event.

### Step 4: Resolve Complaint as Campus Authority (Authority Role)
1. Switch role to **Authority**.
2. Select the assigned authority persona (e.g., `Hostel Warden` or `Chief Warden`).
3. Inspect pending complaints in **My Assigned Queue**.
4. Enter official corrective remarks in the investigation note input (e.g., *"Plumbing contractor replaced damaged joint and inspected corridor wiring"*).
5. Click **Finalize & Mark Resolved**.

### Step 5: Verify Audit Integrity & Attack Simulation (Admin Role)
1. Switch role to **Admin / Oversight** and go to **Tamper-Evident Audit Ledger**.
2. Click **🛡️ Verify Chain Integrity**: The engine recomputes SHA-256 digests across all blocks and displays *“100% Cryptographic Integrity Confirmed”*.
3. Click **🚨 Simulate Silent DB Attack**: Simulates a rogue database administrator silently editing or dismissing a record behind the scenes.
4. Click **Verify Chain Integrity** again: The compromised block and all downstream blocks turn bright red, mathematically proving that unauthorized tampering cannot go undetected.
5. Click **🔄 Restore Ledger** to return to genuine state.

---

## 🎓 Semester 3 Viva Q&A Reference

### 1. System Design
* **Layered Architecture:** Decoupled architecture consisting of a lightweight front-end client, a RESTful API backend, an autonomous SLA scheduler daemon, and isolated storage tiers.
* **API Endpoints:**
  * `POST /api/grievances`: Submits grievance, generates high-entropy token, appends genesis audit record.
  * `GET /api/grievances/{token}`: Fetches public progress, timeline, and SLA countdown without authentication.
  * `PATCH /api/grievances/{id}/status`: RBAC-protected endpoint for authorities to update milestones or resolve complaints.
  * `GET /api/audit/verify`: Verifies blockchain ledger integrity using cryptographic digest comparison.
* **Key Architectural Trade-Off:** Standard relational logging vs. Hash-Chained Audit Ledger. Relational logs can be quietly updated or truncated by database administrators with `UPDATE` or `DELETE` permissions. A hash-chained ledger introduces a minor write compute overhead (`O(1)` SHA-256 hash calculation) in exchange for mathematical tamper-evidence.

### 2. Relational Database Management System (RDBMS - 3NF)
The schema is normalized to **Third Normal Form (3NF)** across 7 distinct tables to eliminate redundancy:
1. `users`: Authority and admin credentials (`user_id`, `role_id`, `name`, `email_hash`, `password_hash`).
2. `roles`: Access levels (`role_id`, `role_name`, `permissions_mask`).
3. `departments`: Institutional units (`dept_id`, `dept_name`, `head_user_id`).
4. `grievances`: Anonymous complaints (`grievance_id`, `receipt_token UNIQUE`, `dept_id`, `urgency`, `title`, `desc`, `current_level`, `assigned_auth_id`, `status`, `created_at`, `due_date`, `resolved_at`). **Zero user_id column.**
5. `escalation_rules`: Departmental escalation matrices (`rule_id`, `dept_id`, `tier_level`, `sla_hours`, `escalate_to_role_id`).
6. `status_history`: Granular chronological events (`history_id`, `grievance_id`, `actor_role`, `action_type`, `remarks`, `timestamp`).
7. `attachments`: Evidence metadata (`attachment_id`, `grievance_id`, `blob_uri`, `file_type`, `sha256_checksum`).

### 3. Microsoft Azure Data Services (DP-900 Alignment)
* **Azure SQL Database (Structured):** Houses the 3NF relational model (grievances, departments, escalation rules) with ACID transaction support.
* **Azure Blob Storage (Unstructured):** Stores uploaded photos and PDF evidence documents with server-side AES-256 encryption and time-limited Shared Access Signature (SAS) tokens.
* **Azure Cosmos DB (Semi-Structured):** Stores JSON audit ledger blocks as append-only immutable records across distributed partitions.
* **Microsoft Power BI:** DirectQuery analytics connected to Azure SQL and Cosmos DB to render hotspot heatmaps and SLA compliance KPIs.

### 4. Cloud Security & Anonymity
* **Zero PII Storage:** No student identification, email address, student ID, IP address, or device fingerprint is logged or stored with complaints.
* **Role-Based Access Control (RBAC):** Students have public anonymous access restricted to filing and token-based lookup; authorities can only view their assigned queues; administrators can access system-wide metrics and audit verification.
* **Secrets Management:** Azure Key Vault isolates storage connection strings and signing keys; credentials are never hardcoded in repository code.
* **Input Sanitization:** Client and server-side sanitation guards against Cross-Site Scripting (XSS) and SQL Injection (SQLi) attacks.

---

## 📁 File Structure
```
sem_3 project/
├── index.html          # Core application container, modals, and navigation
├── css/
│   └── styles.css      # Modern UI design system, light/dark themes, animations
├── js/
│   └── app.js          # State engine, Web Crypto SHA-256, SLA scheduler, analytics
└── README.md           # Project documentation, viva guide & architecture specs
```

