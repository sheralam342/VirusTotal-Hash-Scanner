import time
from datetime import datetime, timezone

import requests
import streamlit as st

VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
SHA256_LENGTH = 64

st.set_page_config(page_title="VirusTotal Hash Scanner", page_icon="🛡️", layout="wide")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def get_api_key() -> str | None:
    """Read the VirusTotal API key from Streamlit secrets."""
    try:
        return st.secrets["VT_API_KEY"]
    except (KeyError, FileNotFoundError):
        return None


def compute_sha256(file_bytes: bytes) -> str:
    """Compute the SHA-256 hash of raw file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def is_valid_hash(value: str) -> bool:
    value = value.strip()
    if len(value) not in (32, 40, 64):
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def query_virustotal(file_hash: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "message": f"Network error: {exc}"}

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "status": "found",
            "hash": file_hash,
            "name": attributes.get("meaningful_name")
            or (attributes.get("names") or [None])[0]
            or "(unknown name)",
            "type": attributes.get("type_description", "unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "last_analysis": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0),
        }

    if response.status_code == 404:
        return {"status": "not_found", "hash": file_hash}

    if response.status_code == 429:
        return {
            "status": "rate_limited",
            "hash": file_hash,
            "message": (
                "VirusTotal rate limit hit (HTTP 429). The free API tier allows "
                "4 requests/minute and 500/day. Wait a bit before trying again."
            ),
        }

    if response.status_code == 401:
        return {
            "status": "error",
            "hash": file_hash,
            "message": "Unauthorized (HTTP 401) — check that VT_API_KEY in secrets.toml is correct.",
        }

    return {
        "status": "error",
        "hash": file_hash,
        "message": f"Unexpected response: HTTP {response.status_code} — {response.text[:200]}",
    }


def verdict_label(result: dict) -> str:
    if result["status"] != "found":
        return "—"
    if result["malicious"] > 0:
        return "🔴 Malicious"
    if result["suspicious"] > 0:
        return "🟠 Suspicious"
    return "🟢 Clean"


def format_timestamp(ts) -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return "—"


def render_result_row(result: dict) -> dict:
    """Flatten a query_virustotal() result into a table row."""
    if result["status"] == "found":
        return {
            "Hash": result["hash"],
            "Verdict": verdict_label(result),
            "Name": result["name"],
            "Type": result["type"],
            "Malicious": result["malicious"],
            "Suspicious": result["suspicious"],
            "Undetected": result["undetected"],
            "Engines": result["total_engines"],
            "Last Analyzed": format_timestamp(result["last_analysis"]),
        }
    if result["status"] == "not_found":
        return {
            "Hash": result["hash"],
            "Verdict": "⚪ Not in VirusTotal",
            "Name": "—", "Type": "—", "Malicious": "—",
            "Suspicious": "—", "Undetected": "—", "Engines": "—",
            "Last Analyzed": "—",
        }
    # rate_limited or error rows are handled with st.warning/st.error, not the table
    return {}


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------

api_key = get_api_key()

with st.sidebar:
    st.header("🛡️ VirusTotal Scanner")
    if api_key:
        st.success("API key loaded from secrets.")
    else:
        st.error(
            "No API key found.\n\n"
            "Add one to `.streamlit/secrets.toml`:\n\n"
            '```toml\nVT_API_KEY = "your_api_key_here"\n```'
        )
    st.caption(
        "Files are never uploaded to VirusTotal — only their SHA-256 "
        "fingerprint is sent for lookup."
    )
    st.caption("Free VirusTotal tier: 4 requests/min, 500/day.")

if "results" not in st.session_state:
    st.session_state.results = []  # list of result dicts, newest first

# --------------------------------------------------------------------------
# Main layout
# --------------------------------------------------------------------------

st.title("VirusTotal Hash Scanner")
st.write(
    "Check a file's reputation against VirusTotal's database of 70+ antivirus "
    "engines, either by uploading a file or entering a hash directly."
)

tab_upload, tab_manual = st.tabs(["📁 Upload File", "🔤 Manual Hash Entry"])

# --- Tab 1: File upload -----------------------------------------------------
with tab_upload:
    st.subheader("Scan an uploaded file")
    uploaded_file = st.file_uploader(
        "Choose a file",
        help="The SHA-256 is computed locally in this app; the file content is not sent anywhere.",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_hash = compute_sha256(file_bytes)
        st.code(file_hash, language=None)
        st.caption(f"File: {uploaded_file.name} ({len(file_bytes):,} bytes)")

        if st.button("Scan this file", type="primary", key="scan_upload"):
            if not api_key:
                st.error("Add VT_API_KEY to secrets.toml before scanning.")
            else:
                with st.spinner("Querying VirusTotal..."):
                    result = query_virustotal(file_hash, api_key)

                if result["status"] == "rate_limited":
                    st.warning(f"⚠️ {result['message']}")
                elif result["status"] == "error":
                    st.error(f"❌ {result['message']}")
                else:
                    st.session_state.results.insert(0, result)
                    if result["status"] == "found" and result["malicious"] > 0:
                        st.error(
                            f"🔴 Flagged as malicious by {result['malicious']} "
                            f"of {result['total_engines']} engines."
                        )
                    elif result["status"] == "found":
                        st.success("🟢 Not flagged as malicious by any engine.")
                    else:
                        st.info("⚪ This hash has no record in VirusTotal (unknown file).")

# --- Tab 2: Manual hash entry -----------------------------------------------
with tab_manual:
    st.subheader("Scan a hash manually")
    manual_hash = st.text_input(
        "Enter a file hash (SHA-256, SHA-1, or MD5)",
        placeholder="e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    ).strip()

    if manual_hash:
        if not is_valid_hash(manual_hash):
            st.error(
                "Invalid hash! A SHA-256 hash must be exactly 64 characters "
                "(SHA-1: 40, MD5: 32), using only 0-9 and a-f."
            )
        elif st.button("Scan this hash", type="primary", key="scan_manual"):
            if not api_key:
                st.error("Add VT_API_KEY to secrets.toml before scanning.")
            else:
                with st.spinner("Querying VirusTotal..."):
                    result = query_virustotal(manual_hash, api_key)

                if result["status"] == "rate_limited":
                    st.warning(f"⚠️ {result['message']}")
                elif result["status"] == "error":
                    st.error(f"❌ {result['message']}")
                else:
                    st.session_state.results.insert(0, result)
                    if result["status"] == "found" and result["malicious"] > 0:
                        st.error(
                            f"🔴 Flagged as malicious by {result['malicious']} "
                            f"of {result['total_engines']} engines."
                        )
                    elif result["status"] == "found":
                        st.success("🟢 Not flagged as malicious by any engine.")
                    else:
                        st.info("⚪ This hash has no record in VirusTotal (unknown file).")

# --------------------------------------------------------------------------
# Results table (shared across both tabs)
# --------------------------------------------------------------------------

st.divider()
st.subheader("Scan Results")

col_a, col_b = st.columns([5, 1])
with col_b:
    if st.button("Clear results"):
        st.session_state.results = []
        st.rerun()

if st.session_state.results:
    rows = [render_result_row(r) for r in st.session_state.results if r.get("status") in ("found", "not_found")]
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    with col_a:
        st.caption("No scans yet — results will appear here as a table.")

st.caption(
    "Rate-limit note: the free VirusTotal API allows 4 requests/minute and "
    "500/day. A 429 response means you've hit that limit — space out your scans."
)
