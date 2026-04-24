# 🎣 PhishIntel v1.0 (PhishOps)

An advanced, real-time phishing detection platform. PhishOps combines Machine Learning (Random Forest + SHAP), secure DOM extraction via Playwright, and active DNS/IP reconnaissance to identify and neutralize malicious web domains.

---

## ✨ Key Features

* **🧠 Machine Learning Detection:** Utilizes a Random Forest Classifier trained on the UCIML Phishing Dataset. Features SHAP (SHapley Additive exPlanations) for transparent, feature-level threat scoring.
* **🛡️ Sandboxed Feature Extraction:** Safely analyzes potentially malicious URLs using a decoupled, highly-restricted Playwright Chromium container (stripped of privileges to prevent host DoS or escapes).
* **🌍 Real-Time Threat Globe:** A highly interactive 3D threat map powered by Three.js and GeoIP lookups, visualizing malicious infrastructure origins globally.
* **🕵️ DNS Reconnaissance:** Deep dives into target domains to extract DNS records (A, MX, SPF, NS, SOA) and queries AbuseIPDB for real-time threat intelligence.
* **⚡ Live Command Center:** A TailwindCSS-powered dark mode dashboard utilizing WebSockets for a live feed of scanned URLs, threat status, and visual screenshot captures.
* **🚀 Automated CI/CD:** Integrated GitHub Actions workflow (`deploy.yml`) for seamless, zero-downtime deployments to Oracle Cloud via SSH and Docker Compose.

---

## 🏗️ Architecture & Stack

### Backend
* **Framework:** FastAPI, Uvicorn
* **Machine Learning:** Scikit-Learn, SHAP, Pandas, Numpy, Joblib
* **Feature Extraction:** Playwright (Async), BeautifulSoup4
* **Networking/OSINT:** DNS Python, tldextract, Requests (AbuseIPDB API)

### Frontend
* **UI/Styling:** HTML5, TailwindCSS (via CDN)
* **Interactivity:** Vanilla JS (`script.js`), WebSockets (for live feeds)
* **Visualization:** Three.js (`threatmap.html`)

### DevOps & Deployment
* **Containerization:** Docker, Docker Compose (Multi-container architecture: `app` + `playwright`)
* **CI/CD:** GitHub Actions (`deploy.yml`)

---
🛠️ Installation & Setup
Prerequisites
Docker and Docker Compose

Git

Running Locally (Dockerized)
The easiest and safest way to run PhishOps is via Docker Compose, as it sets up the secure Playwright sandbox automatically.

Clone the repository:

Bash
git clone [https://github.com/JasserBkr/URL-PHISHING-DETECTION]
cd URL-PHISHING-DETECTION

Build and start the containers:

Bash
docker compose up -d --build
Access the application:

Command Center: http://localhost:8000

DNS Recon: http://localhost:8000/dns_recon.html

Threat Map: http://localhost:8000/threatmap.html

🔐 Security Considerations
Malicious websites often utilize browser exploits or crypto-miners. To mitigate this, the Playwright service runs in a heavily restricted Docker container (Dockerfile.playwright & Docker-compose.yml):

