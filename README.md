# VirusTotal Hash Scanner

A Streamlit app that checks file hashes against the [VirusTotal](https://www.virustotal.com) API — either by uploading a file (hashed locally) or by entering a hash directly.

## Features

- **Upload File tab** — computes the SHA-256 of an uploaded file in your browser session; only the hash is sent to VirusTotal, never the file itself.
- **Manual Hash Entry tab** — paste a SHA-256, SHA-1, or MD5 hash to look up directly.
- **Results table** — verdict, detection counts, file name/type, and last analysis date, shared across both tabs.
- **Secrets-based API key** — read from `st.secrets`, never hardcoded or logged.
- **Rate-limit handling** — a clear warning on HTTP 429, plus distinct messages for 401 (bad key) and 404 (hash not found).

## Setup

1. **Get a free VirusTotal API key**
   Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us) and copy your key from [your API key page](https://www.virustotal.com/gui/my-apikey).

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Add your API key**
   Rename `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in your key:
   ```toml
   VT_API_KEY = "your_api_key_here"
   ```
   `secrets.toml` is already listed in `.gitignore` — never commit it.

4. **Run the app**
   ```bash
   streamlit run app.py
   ```
   It opens at `http://localhost:8501`.

## Project files

| File | Purpose |
|---|---|
| `app.py` | The Streamlit app |
| `requirements.txt` | Python dependencies |
| `.streamlit/secrets.toml.example` | Template for your API key — rename and fill in |
| `.gitignore` | Keeps `secrets.toml` and caches out of version control |

## Testing safely

Don't test with real malware. Safe options:

- **[EICAR test file](https://www.eicar.org/)** — a harmless, industry-standard file that antivirus engines are designed to flag as a threat.
- **Known-clean files** — any ordinary document or image should come back "Clean" or "Not in VirusTotal."
- **A known-bad hash** — paste a public, well-documented malware hash (from a threat-intel writeup, not a live sample) into the Manual Hash Entry tab to see a "Malicious" verdict without ever touching the file.

## API limits (free tier)

- 4 requests per minute
- 500 requests per day

Hitting either limit returns HTTP 429, which the app surfaces as an on-screen warning rather than a crash.

## Troubleshooting

| Problem | Fix |
|---|---|
| "No API key found" in the sidebar | Check `.streamlit/secrets.toml` exists and `VT_API_KEY` is set correctly |
| "Unauthorized (HTTP 401)" | Your API key is invalid or mistyped |
| "Rate limit hit (HTTP 429)" | Wait a minute (or until the next day) before scanning again |
| "Invalid hash!" | Hash must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters, no spaces |
