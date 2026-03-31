# FusionIDS — Docker Containerization Guide

## Project Structure After Adding Docker Files

```
project-root/
├── traffic_capturer_updated/
│   └── Dockerfile                  ← NEW
├── updated_model/
│   ├── Dockerfile                  ← NEW
│   └── requirements.txt            ← NEW (verify packages match your code)
├── updated_blockchain/
│   ├── Dockerfile                  ← NEW
│   ├── requirements.txt            ← NEW (verify packages match your code)
│   └── module3/
│       └── config.py               ← REPLACE with config_updated.py
├── models/                         ← NEW folder — put your .pkl/.joblib files here
├── docker-compose.yml              ← NEW
└── .env                            ← NEW (copy from .env.example)
```

---

## Step-by-Step Setup

### 1. Place the new files

Copy the generated files into your repo:

| Generated file            | Destination in repo                          |
|---------------------------|----------------------------------------------|
| `capturer/Dockerfile`     | `traffic_capturer_updated/Dockerfile`        |
| `ml-server/Dockerfile`    | `updated_model/Dockerfile`                   |
| `blockchain/Dockerfile`   | `updated_blockchain/Dockerfile`              |
| `ml_requirements.txt`     | `updated_model/requirements.txt`             |
| `blockchain_requirements.txt` | `updated_blockchain/requirements.txt`   |
| `config_updated.py`       | `updated_blockchain/module3/config.py`       |
| `docker-compose.yml`      | project root                                 |
| `.env.example`            | project root (then `cp .env.example .env`)   |

### 2. Add your trained model files

```bash
mkdir -p models/
# Copy your trained files here, e.g.:
cp path/to/signature_model.pkl   models/
cp path/to/anomaly_model.joblib  models/
```

The `models/` folder is mounted read-only into the ml-server container at `/app/models`.
Make sure your `FusionIDS` / `anomaly_detector.py` / `signature_predictor.py` load from
a path like `../models/` or use an env variable — adjust if needed.

### 3. Verify requirements.txt files

The generated `requirements.txt` files are best guesses based on the code.  
Open each one and add or remove packages to match your actual imports:

```bash
# For ML server — check what fusion_ids.py, anomaly_detector.py etc. import
nano updated_model/requirements.txt

# For blockchain — check what BlockChain.py, PBFT.py, NodeApi.py import
nano updated_blockchain/requirements.txt
```

### 4. Fix the network interface in .env

```bash
ip link   # find your active NIC name, e.g. eth0, ens3, wlan0
nano .env
# Set: CAPTURE_INTERFACE=eth0
```

### 5. Build and run

```bash
docker compose up --build
```

First build takes ~3–5 min (compiling C++, installing Python deps).
Subsequent starts are fast.

---

## ⚠️ Critical: The localhost Problem in config.py

`config.py` originally used `http://localhost:500X` for peer URLs.  
**This breaks in Docker** — each container has its own localhost.

The replacement `config_updated.py` reads peer URLs from environment variables:
```
PEER_0_URL=http://blockchain-node-0:5000
PEER_1_URL=http://blockchain-node-1:5001
...
```

These are set automatically by `docker-compose.yml`. No manual editing needed.

---

## ⚠️ Critical: Capturer Uses host Networking

The capturer needs raw access to the host's NIC, so it runs with:
```yaml
network_mode: host
cap_add: [NET_RAW, NET_ADMIN]
```

This means **the capturer cannot reach other containers by service name**.  
It reaches the ML server via `http://127.0.0.1:8000` (which works because
the ML server's port 8000 is published to the host).

If your `FeatureSender.hpp` hardcodes `localhost:8000`, it will work.  
If it reads from an env variable, set `ML_SERVER_URL=http://127.0.0.1:8000` in `.env`.

---

## Service Map

```
                    ┌─────────────────────────────────────────────────┐
  HOST NETWORK      │                                                 │
                    │   capturer  ──HTTP POST /predict──►  ml-server  │
                    │   (C++)          127.0.0.1:8000      port 8000  │
                    └───────────────────────┬─────────────────────────┘
                                            │ ids-net (bridge)
                            HTTP POST /alert│
                                            ▼
                              blockchain-node-0 :5000  (leader)
                                    │  │  │
                         PBFT      ▼  ▼  ▼
                      node-1:5001  node-2:5002  node-3:5003
                      (each has its own SQLite DB volume)
                      (each calls ml-server /validate for peer verification)
```

---

## Useful Commands

```bash
# Start everything
docker compose up --build -d

# View logs for a specific service
docker compose logs -f ml-server
docker compose logs -f capturer
docker compose logs -f blockchain-node-0

# Check ML server health
curl http://localhost:8000/health

# Check blockchain node health
curl http://localhost:5000/health

# Stop everything
docker compose down

# Stop and wipe all blockchain DB volumes (full reset)
docker compose down -v
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `capturer` exits immediately | ML server not ready | Already handled by `depends_on: service_healthy` |
| `ModuleNotFoundError` in ml-server | Missing package in requirements.txt | Add it and rebuild |
| Blockchain nodes can't reach each other | config.py not updated | Replace with config_updated.py |
| Model file not found | Wrong path in FusionIDS | Check where your code loads models from and adjust volume mount |
| `libpcap not found` at build | Docker cache issue | `docker compose build --no-cache capturer` |
| Permission denied on packet capture | Missing capabilities | Ensure `cap_add: [NET_RAW, NET_ADMIN]` is in docker-compose.yml |
