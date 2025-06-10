# TriNetra 🔱

*The Third Eye that Sees Beyond the Surface..🔎🌐*

```text
╔╦╗┬─┐┬╔╗╔┌─┐┌┬┐┬─┐┌─┐
 ║ ├┬┘│║║║├┤  │ ├┬┘├─┤
 ╩ ┴└─┴╝╚╝└─┘ ┴ ┴└─┴ ┴
```

&#x20;

> **TriNetra** is a fast, smart, multi-threaded crawler that digs *below* the surface of your target web-site to uncover hidden endpoints, API keys, and JWTs. Built for bug-hunters, penetration testers and OSINT researchers, it combines coloured Rich output with powerful features like Tor routing and CSRF-aware requests
> — all from the comfort of your terminal.

---

## ✨ Features

* 🚀 **High-performance** threaded crawler (configurable worker pool)
* 🌐 **HTML / JS / sitemap / robots.txt** link extraction
* 🔑 **JWT & API-key** candidate discovery
* 🧅 **Tor & proxy** support (HTTP/SOCKS)
* 🛡️ **CSRF token** fetch / inject workflow
* ⚡ **HTTP/2** option via *httpx*
* 🎨 Polished **Rich** CLI with colour tables & panels
* 💾 Export to **JSON** and/or **CSV**
* 🐍 100 % **Python** — no external binaries required

---

## 📦 Installation

```bash
# 1. Clone
git clone https://github.com/yourname/TriNetra.git
cd TriNetra

# 2. (Recommended) Create virtual-env
python3 -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Performance extras
pip install lxml httpx[socks]
```

Python **3.8+** is required.

---

## 📘 Usage

See [docs/usage.md](docs/usage.md) for full CLI options and examples.

---

## 📝 Output format

JSON report structure:

```json
[
  {
    "target": "https://example.com",
    "endpoints": [
      { "endpoint": "https://example.com/hidden/api", "source": "https://example.com/dashboard" }
    ],
    "jwt_candidates": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    "api_keys": ["7f12e9cd513b4d0d..."]
  }
]
```

CSV report (when `--csv file.csv`) contains one row per endpoint with optional *Source* column.

---

## 📂 Repository layout

```text
TriNetra/
├── README.md           # You are here!
├── TriNetra.py         # Main executable script
├── requirements.txt    # Pinned dependencies
├── .gitignore          # Common Python ignores
├── LICENSE             # MIT
├── docs/               # Additional docs & screenshots
│   └── usage.md
├── examples/           # Sample raw requests & wordlists
│   └── sample_request.txt
└── .github/            # CI / templates (optional)
    ├── workflows/ci.yml
    └── ISSUE_TEMPLATE.md
```

---

## 🤝 Contributing

Pull-requests and feature suggestions are welcome! Please open an issue first to discuss major changes.

1. Fork the project & create a new branch.
2. Commit your changes with clear messages.
3. Open a PR describing *what* & *why*.

Check *[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)* for coding guidelines.

---

## 🛡️ License

TriNetra is released under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

*Rich*, *Requests*, *BeautifulSoup*, *httpx*, and the broader open-source community made this project possible.

> *May TriNetra be your third eye in the hunt for obscure attack surface!*
