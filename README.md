# Cybersecurity Companion

A privacy-first desktop security tool built for small businesses and students who can't afford cloud-based enterprise software. Everything runs locally — no data leaves your machine.

---

## What it does

- **Phishing detection** — checks URLs against a locally trained Random Forest model before the page even loads
- **Log anomaly scanner** — uses Isolation Forest to flag weird patterns in your system logs
- **Hardened browser** — built on Chromium via PyQt6, with download interception and tracker blocking baked in
- **Offline AI assistant** — a RAG-based chatbot that answers security questions using a local knowledge base (no internet required)
- **Security training module** — a quiz system with XP and leveling to actually make users care about security hygiene

---

## Why local-only?

Sending URLs or log data to a cloud API is a compliance problem for anyone under GDPR or HIPAA. This tool keeps all inference on-device — the ML models run on your CPU, the knowledge base is stored on your disk, and the SQLite database never syncs anywhere.

It also runs fine on older hardware. Tested on dual-core machines with integrated graphics.

---

## Getting started

### Requirements

- Python 3.10+
- Windows (tested on 10 and 11)

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the app

```bash
run.bat
```

or manually:

```bash
python main.py
```

---

## Project layout

```
cybersecurity_companion/
├── main.py                  # entry point
├── config.py                # all paths, thresholds, and constants
├── requirements.txt
├── run.bat
│
├── assistant/               # RAG chatbot (FAISS + sentence transformers)
├── auditor/                 # model integrity checks
├── browser/                 # download manager, privacy tools, security analyzer
├── database/                # SQLite setup and queries
├── detection/               # phishing + anomaly ML models
├── gamification/            # XP system and quiz engine
├── security/                # input validation and policy enforcement
├── ui/                      # all PyQt6 tabs and windows
├── utils/                   # background workers and helpers
│
├── assets/                  # icons and UI images
├── data/                    # runtime data (SQLite db, knowledge base)
└── models/                  # trained model files (.pkl, .faiss)
```

---

## Building an executable

To package this as a standalone `.exe` (no Python install needed):

```bash
build_exe.bat
```

The output goes to `dist/`. The spec file (`build.spec`) handles asset bundling and runtime hooks for PyTorch.

---

## Tech stack

| Component | Library |
|---|---|
| GUI + Browser | PyQt6 / QtWebEngine |
| Phishing ML | scikit-learn (Random Forest) |
| Anomaly ML | scikit-learn (Isolation Forest) |
| AI Assistant | sentence-transformers + FAISS |
| Database | SQLite (via Python stdlib) |

---

## Notes

- First run will train and save the ML models to `models/` — this takes a few seconds
- The knowledge base for the AI assistant is in `data/knowledge_base.json` — you can add your own entries
- Hardware acceleration is disabled by default to ensure stability on low-spec machines

---

## License

See `LICENSE` file.
