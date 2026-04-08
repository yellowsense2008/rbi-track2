# AppGuard: Financial Threat Intelligence Pipeline

Most mobile security tools just scan an app's manifest and take its word for what it does. AppGuard actually detonates it. 

This is a dual-stage threat intelligence engine designed to detect financial malware, bypass modern sandbox evasion tactics, and map out the offshore network infrastructure used by scam cartels. It acts as the backend engine for a B2B Threat Graph.

## 🏗️ The Architecture

AppGuard processes APKs using a Just-In-Time enrichment model. The analysis happens in two distinct stages to catch both structural and behavioral evasion.

### Stage 1: Static OSINT & ML (The Front Door)
When an APK is uploaded, the engine tears it apart without executing it. 
* **Ghost App Detection:** We verify the package against official app stores. If it isn't listed, it gets flagged as a "Ghost App" and hit with a critical risk penalty for bypassing regulatory transparency.
* **OSINT Checks:** The engine scans domain registration age, verifies RBI registry status, and flags burner email addresses (e.g., free Gmail accounts claiming to be banks).
* **Evasion Guardrails:** If malware intentionally corrupts its own manifest to break security parsers, Stage 1 catches the anomaly and immediately rejects it.

### Stage 2: Dynamic Detonation (The Sandbox)
FastAPI hands the APK over to a local MobSF Docker container via a background task. 
* The sandbox installs the malware on an Android emulator and records its behavior.
* **Network Harvesting:** We extract the raw network traffic to find the offshore IP addresses and hidden trackers the app tries to contact.
* **Behavioral Evasion Detection:** If a smart app realizes it is in an emulator and intentionally "plays dead" (generating zero network traffic), our custom logic overrides the sandbox and flags it as highly evasive.

## 🕸️ The Cartel Batch Processor

If you are a security researcher analyzing a massive dump of malware to build a Threat Graph, do not use the single-file API manually. 

Run the batch processor:

```bash
python routers/cartel_mapper.py
```

This script automatically chews through the `cartel_samples` directory. It handles emulator timeouts, skips corrupted files, and aggregates the data into a final `cartel_graph_data.json` file. This JSON contains the nodes and edges required to visualize the entire cartel network in frontend libraries like React Flow or D3.js.

## 💻 Local Setup

You need Docker to run the sandbox environment, and Python 3.10+ for the AppGuard engine.

**1. Start the Sandbox** You must run MobSF with a static API key so the AppGuard backend can authenticate automatically.

```bash
sudo docker run -it -d -p 8001:8000 -e MOBSF_API_KEY="hackathon_rbi_key_2026" opensecurity/mobile-security-framework-mobsf:latest
```

**2. Start the Engine** Set up your virtual environment, install dependencies, and start the FastAPI server.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

The API will be live at `http://localhost:8000`.
