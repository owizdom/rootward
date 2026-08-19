"""Which side of the enclave boundary a file runs on.

Most of this catalog assumes the code it reads runs *inside* the enclave. "A secret written
to a log sink reaches the operator" is true in the guest; the same line in an operator's own
CLI is that CLI printing to that operator's terminal. A timing side channel needs a remote
attacker who can measure it, not a local script. Without the distinction the tool reports a
platform's host-side tooling as if it were enclave code.

This is the second attempt. The first classified `dstack-util/src/system_setup.rs` as host
because it parses clap arguments, and that file is guest code holding the findings most
worth keeping. It was deleted rather than shipped. The rules below exist because of that:

**`unknown` is audited.** Only `host` suppresses anything, so a wrong `unknown` costs noise
and a wrong `host` costs a missed vulnerability. Everything unresolved resolves to `unknown`.

**`host` needs two independent signals.** One signal is a coincidence. A path under `tools/`
is not evidence; a path under `tools/` containing a browser bundle is.

**A guest-only call vetoes everything.** Opening `/dev/tdx_guest` or calling
`nsm_process_request` settles it whatever the path looks like. A *mention* does not: matching
vocabulary is how the first attempt failed, and how platform detection used to read
CHANGELOG.md.

**The repository can just tell us.** `rootward.toml` with `guest`/`host` glob lists is
authoritative. Most projects know their own boundary and asking beats guessing.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

GUEST, HOST, UNKNOWN = "guest", "host", "unknown"

# Calls, not mentions. Each of these is an interface only a guest has, used as a call or an
# open, so a document discussing TDX cannot trip it.
GUEST_CALL = re.compile(
    r"(?i)("
    r"[\"'`]/dev/(tdx[-_]guest|sev-guest|nsm)[\"'`]|"          # opening the device
    r"\bnsm_(init|process_request|get_random)\s*\(|"
    r"\bTdxAttest\w*::|tdx_attest::|\bget_quote\s*\(|"
    r"[\"'`]/var/run/(tappd|dstack)\.sock[\"'`]|"
    r"\bRTMR\d\s*[,)=]|extend_rtmr\s*\("
    r")"
)

# Structural host signals. Each is one vote; two are needed.
BROWSER_BUNDLE = re.compile(r"(?i)\b(vue|react|svelte|@vitejs|next|nuxt|webpack|vite)\b")
IAC_DIR = re.compile(r"(?i)(^|/)(terraform|helm|charts|k8s|kubernetes|ansible|pulumi)(/|$)")
TOOLING_DIR = re.compile(r"(?i)(^|/)(scripts?|tools?|hack|devtools?|ui|web|frontend|dashboard)(/|$)")
ARG_PARSER = re.compile(
    r"(?i)(argparse\.ArgumentParser|click\.command|typer\.Typer|commander|yargs)"
)
REMOTE_CONTROL_PLANE = re.compile(
    r"(?i)(requests\.(get|post|put|delete)\s*\(|httpx\.|urllib\.request|axios\.|"
    r"\bfetch\s*\(\s*[\"'`]https?://|boto3\.client)"
)
INSTALLER = re.compile(r"(?i)(^|/)(install|installer|setup)\.(sh|py|rs|ts)$|(^|/)Makefile$")


class Boundary:
    """Classifier for one audit root. Loads `rootward.toml` once if it is present."""

    def __init__(self, root: Path):
        self.root = root
        self.declared_guest: list[str] = []
        self.declared_host: list[str] = []
        self._load_declaration()

    def _load_declaration(self) -> None:
        cfg = self.root / "rootward.toml"
        if not cfg.is_file():
            return
        try:
            import tomllib

            data = tomllib.loads(cfg.read_text(encoding="utf-8"))
        except (OSError, ValueError, ImportError):
            return
        section = data.get("boundary") or {}
        self.declared_guest = [str(x) for x in (section.get("guest") or [])]
        self.declared_host = [str(x) for x in (section.get("host") or [])]

    @property
    def declared(self) -> bool:
        return bool(self.declared_guest or self.declared_host)

    def classify(self, rel: str, text: str | None = None) -> str:
        # 1. An explicit declaration wins outright.
        for pattern in self.declared_guest:
            if fnmatch.fnmatch(rel, pattern):
                return GUEST
        for pattern in self.declared_host:
            if fnmatch.fnmatch(rel, pattern):
                return HOST

        if text is None:
            try:
                text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return UNKNOWN

        # 2. A guest-only call settles it.
        if GUEST_CALL.search(text):
            return GUEST

        # 3. Otherwise host must earn two independent votes.
        votes = []
        if IAC_DIR.search(rel):
            votes.append("infrastructure-as-code directory")
        if TOOLING_DIR.search(rel):
            votes.append("tooling directory")
        if BROWSER_BUNDLE.search(text) and re.search(r"(?i)\.(ts|js|vue|jsx|tsx)$", rel):
            votes.append("browser bundle")
        if ARG_PARSER.search(text) and REMOTE_CONTROL_PLANE.search(text):
            votes.append("CLI against a remote control plane")
        if INSTALLER.search(rel):
            votes.append("installer")

        return HOST if len(votes) >= 2 else UNKNOWN
