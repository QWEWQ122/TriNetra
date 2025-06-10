# Contributing to TriNetra

First off, thanks for your interest in contributing! 🫡

We welcome pull requests, bug reports, and suggestions. Here's a quick guide to help you get started.

---

## 🧰 Setup

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/TriNetra.git
   cd TriNetra
   ```
3. Install the dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
4. (Optional) Install extras for linting and dev support:

   ```bash
   pip install flake8 httpx[socks] lxml
   ```

---

## 🚧 Guidelines

* Use feature branches: `git checkout -b feature/my-feature`
* Keep PRs small and focused on a single change
* Write meaningful commit messages
* Format with `black` and check with `flake8`:

  ```bash
  black TriNetra.py
  flake8 TriNetra.py --max-line-length=120
  ```
* Include tests or examples where applicable
* Add your name in the contributors section (optional)

---

## ✅ Submitting a Pull Request

1. Push your feature branch to your fork
2. Go to the GitHub repo and open a Pull Request
3. Fill out the PR template:

   * What does this PR do?
   * Why is it needed?
   * Does it break anything?

---

## 🐛 Reporting Issues

Use the [ISSUE\_TEMPLATE.md](../.github/ISSUE_TEMPLATE.md) to report bugs and feature ideas. Please include:

* Steps to reproduce (if applicable)
* Expected vs actual behavior
* Environment details (OS, Python version)
* Screenshots or logs when possible

---

## 🙏 Thanks again!

Your effort makes open-source better for everyone. Happy hunting with TriNetra! 🔎
