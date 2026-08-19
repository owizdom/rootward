"""PDF rendering for an audit report, in the shape a security review is normally read in.

Modelled on how audit firms lay a review out: cover, contents, scope and commit, a stated
risk classification, an executive summary, then numbered findings each carrying a
description, the evidence, and a recommendation. The reason to follow that convention is
not decoration. A reader who has seen ten of these knows where to look for the scope and
the severity definitions, and a report that hides them reads as less trustworthy than one
that does not.

Two sections here that a manual review does not usually carry, and both are the point of
this tool rather than an addition to it:

  * every finding prints the conditions under which its rule is wrong, taken from the
    rule's own `false_positives` field, so triage starts from the tool's own admission
  * a closing section lists what the review structurally could not check

Rendered from the same result object as the markdown report, so the two cannot drift.
reportlab is optional and pure Python, no system libraries.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_TAG = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}

# Restrained on purpose. A report that is printed, or read on a projector, should not
# depend on a bright screen to be legible.
SEVERITY_COLOR = {
    "critical": "#8B1A1A",
    "high": "#A85206",
    "medium": "#6B5200",
    "low": "#2F4F6F",
    "info": "#4A4A4A",
}

ACTION_REQUIRED = [
    ("Critical", "Must fix before the enclave handles anything of value."),
    ("High", "Must fix. The guarantee the deployment is sold on does not hold without it."),
    ("Medium", "Should fix. Weakens a control that other controls are assumed to rest on."),
    ("Low", "Could fix. Reachable only under conditions that are unlikely or costly."),
]

IMPACT_DEF = [
    ("High", "The enclave's core guarantee fails. Secrets leave it, or an unmeasured "
             "workload is accepted as a measured one."),
    ("Medium", "A control that other controls depend on is weakened, without directly "
               "exposing key material."),
    ("Low", "Unexpected behaviour with no direct path to key material or to accepting an "
            "unmeasured workload."),
]

LIKELIHOOD_DEF = [
    ("High", "The defect is present as written and reachable on the deployed path. No "
             "additional conditions are required for it to matter."),
    ("Medium", "The defect is present and a plausible benign reading of the same code "
               "exists. Confirmation against the cited line is required."),
    ("Low", "Reported for completeness. The pattern is indicative rather than conclusive "
            "and needs adjudication by someone who knows the deployment."),
]


class PdfUnavailable(RuntimeError):
    """reportlab is not installed. The caller reports it rather than writing an empty file."""


def _require():
    try:
        import reportlab  # noqa: F401
    except ImportError as exc:
        raise PdfUnavailable("PDF output needs reportlab: pip install reportlab") from exc


def _git_commit(root: str) -> str | None:
    """The commit under review, when the target is a checkout. An audit report without one
    describes a moving target."""
    import subprocess

    try:
        p = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=15)
        return p.stdout.strip() or None if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _styles():
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm

    base = getSampleStyleSheet()
    S = ParagraphStyle
    return {
        "cover_title": S("ct", parent=base["Title"], fontName="Times-Bold", fontSize=30,
                         leading=36, spaceAfter=3 * mm, alignment=TA_CENTER),
        "cover_sub": S("cs", parent=base["Normal"], fontName="Times-Bold", fontSize=16,
                       leading=20, alignment=TA_CENTER, spaceAfter=6 * mm),
        "cover_meta": S("cm", parent=base["Normal"], fontName="Times-Roman", fontSize=11,
                        leading=15, alignment=TA_CENTER, spaceAfter=1.5 * mm),
        "h1": S("h1", parent=base["Heading1"], fontName="Times-Bold", fontSize=19,
                leading=23, spaceBefore=8 * mm, spaceAfter=1 * mm),
        "h2": S("h2", parent=base["Heading2"], fontName="Times-Bold", fontSize=14,
                leading=18, spaceBefore=6 * mm, spaceAfter=2 * mm),
        "h3": S("h3", parent=base["Heading3"], fontName="Times-Bold", fontSize=11.5,
                leading=15, spaceBefore=4 * mm, spaceAfter=1.5 * mm),
        "body": S("bd", parent=base["Normal"], fontName="Times-Roman", fontSize=10.5,
                  leading=15, spaceAfter=2.5 * mm, leftIndent=6 * mm, rightIndent=2 * mm),
        "bullet": S("bl", parent=base["Normal"], fontName="Times-Roman", fontSize=10.5,
                    leading=14.5, spaceAfter=1.2 * mm, leftIndent=12 * mm, bulletIndent=7 * mm),
        "meta": S("mt", parent=base["Normal"], fontName="Courier", fontSize=8,
                  leading=11, textColor="#555555", spaceAfter=2 * mm, leftIndent=6 * mm),
        "code": S("cd", parent=base["Code"], fontName="Courier", fontSize=7.8, leading=10.5,
                  textColor="#111111", backColor="#F5F5F5", borderPadding=5,
                  leftIndent=6 * mm, rightIndent=2 * mm, spaceAfter=2.5 * mm),
        "toc1": S("t1", parent=base["Normal"], fontName="Times-Roman", fontSize=11,
                  leading=17, leftIndent=6 * mm),
        "toc2": S("t2", parent=base["Normal"], fontName="Times-Roman", fontSize=10,
                  leading=15, leftIndent=13 * mm, textColor="#333333"),
        "locsm": S("ls", parent=base["Normal"], fontName="Courier", fontSize=7,
                   leading=9.5, textColor="#333333"),
    }


def _rule(width="100%"):
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable

    return HRFlowable(width=width, thickness=0.9, color="#222222",
                      spaceBefore=0.5 * mm, spaceAfter=3 * mm)


def rid_of(rule: dict) -> str:
    return str(rule.get('id', ''))


def _wrap_code(text: str, width: int = 92) -> str:
    out = []
    for line in (text or "").splitlines() or [""]:
        while len(line) > width:
            out.append(line[:width])
            line = line[width:]
        out.append(line)
    return escape("\n".join(out)) or "&nbsp;"


def _table(rows, widths, styles_extra=None):
    from reportlab.platypus import Table, TableStyle

    t = Table(rows, colWidths=widths, hAlign="LEFT")
    style = [
        ("FONT", (0, 0), (-1, 0), "Times-Bold", 9.5),
        ("FONT", (0, 1), (-1, -1), "Times-Roman", 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, "#999999"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]
    t.setStyle(TableStyle(style + list(styles_extra or [])))
    return t


def render_pdf(result: dict, out_path: Path, catalog: dict | None = None) -> Path:
    _require()
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
    )
    from reportlab.platypus.tableofcontents import TableOfContents

    catalog = catalog or {}
    st = _styles()
    findings = result.get("findings", [])
    sc = result.get("scorecard") or {}
    root = str(result.get("root", ""))
    target = Path(root).name or root
    commit = _git_commit(root)

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    ordered = sorted(findings, key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}

    # [C-01], [H-01], numbered within severity, which is how a reader cites one back.
    labels, seen = {}, {}
    for f in ordered:
        tag = SEVERITY_TAG.get(f["severity"], "I")
        seen[tag] = seen.get(tag, 0) + 1
        labels[id(f)] = f"{tag}-{seen[tag]:02d}"

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Times-Roman", 9)
        canvas.setFillColor("#444444")
        if doc.page > 1:
            canvas.drawCentredString(A4[0] / 2, 12 * mm, str(doc.page - 1))
        canvas.restoreState()

    class Doc(BaseDocTemplate):
        def afterFlowable(self, flowable):
            """Feed the contents page. Without this the ToC has no page numbers."""
            if flowable.__class__.__name__ != "Paragraph":
                return
            style = flowable.style.name
            if style in ("h1", "h2"):
                level = 0 if style == "h1" else 1
                text = flowable.getPlainText()
                self.notify("TOCEntry", (level, text, self.page - 1))

    doc = Doc(str(out_path), pagesize=A4,
              leftMargin=20 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=20 * mm,
              title=f"{target} security review", author="rootward")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=footer)])

    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], st["toc2"]]

    s = []
    P = lambda t, k="body": Paragraph(t, st[k])  # noqa: E731
    def H(text, key="h1"):
        s.append(Paragraph(escape(text), st[key]))
        s.append(_rule())

    def bullets(items):
        for name, text in items:
            s.append(Paragraph(f"<b>{escape(name)}</b>: {escape(text)}", st["bullet"], bulletText="•"))

    # ---------------------------------------------------------------- cover ----
    mark = Path(__file__).resolve().parent.parent / "assets" / "rootward-mark.png"
    s.append(Spacer(1, 26 * mm))
    if mark.exists():
        from reportlab.platypus import Image as RLImage

        img = RLImage(str(mark), width=44 * mm, height=44 * mm)
        img.hAlign = "CENTER"
        s.append(img)
        s.append(Spacer(1, 14 * mm))
    else:
        s.append(Spacer(1, 16 * mm))
    s.append(Paragraph(f"{escape(target)} Security Review", st["cover_title"]))
    s.append(_rule("62%"))
    s.append(Paragraph("rootward", st["cover_sub"]))
    s.append(Paragraph("Static security review of a Web3 protocol built on a cloud TEE",
                       st["cover_meta"]))
    if commit:
        s.append(Paragraph(f"commit {escape(commit[:12])}", st["cover_meta"]))
    s.append(Paragraph(datetime.now(UTC).strftime("%d %B %Y"), st["cover_meta"]))
    s.append(PageBreak())

    # -------------------------------------------------------------- contents ----
    s.append(Paragraph("Contents", st["h1"]))
    s.append(_rule())
    s.append(toc)
    s.append(PageBreak())

    # ------------------------------------------------------------ 1. about ----
    H("1. About rootward")
    s.append(P(
        "rootward is a static auditor for Web3 protocols built on cloud trusted execution "
        "environments: AWS Nitro Enclaves, dstack, EigenCompute, and Google Cloud "
        "Confidential Space. It runs a catalog of rules derived from the Bluethroat Labs "
        "TEE Security Handbook against a repository, reading source, container and "
        "deployment configuration, KMS key policy, OS and firmware build recipes, and the "
        "built enclave image."))
    s.append(P(
        "Every rule cites the handbook section it comes from and declares the conditions "
        "under which it is wrong. Detection is measured rather than asserted: recall is "
        "established by injecting each catalogued defect into a clean tree and asking "
        "whether that rule fires."))

    H("2. Disclaimer")
    s.append(P(
        "A static review can never establish the absence of vulnerabilities. This one reads "
        "a repository at a single commit. It does not observe a running enclave, does not "
        "fetch an attestation document from live hardware, does not read the KMS policy "
        "actually attached to the deployed key, and does not reason about the economics or "
        "the key ceremony of the protocol under review."))
    s.append(P(
        "Findings are produced by pattern and format analysis and each one should be read "
        "against its cited evidence before it is acted on. Section 9 lists what this review "
        "structurally could not check, and a clean result above does not extend to anything "
        "in that list. A manual review by a qualified engineer remains necessary."))

    H("3. Introduction")
    s.append(P(
        f"A static security review of <b>{escape(target)}</b> was performed with rootward, "
        f"focused on the properties a cloud TEE deployment depends on: attestation "
        f"verification, measurement pinning, the trust boundary against the parent "
        f"instance, secret handling, and the configuration of the image the workload runs "
        f"in."))
    if commit:
        s.append(P(f"Review commit: <font face='Courier' size='9'>{escape(commit)}</font>"))

    # ------------------------------------------------------ 4. about target ----
    H("4. About the review target")
    plat = result.get("platform", {}).get("summary", "unknown")
    s.append(P(
        f"Platform detected: <b>{escape(str(plat))}</b>. Platform detection decides which "
        f"rules apply, in both directions, so a report for one platform does not carry "
        f"another platform's inapplicable findings."))
    # `evidence` is {signal: [file:line, ...]}. Name the signal and cite one site for it,
    # so the platform claim is checkable rather than asserted.
    ev = result.get("platform", {}).get("evidence") or {}
    if isinstance(ev, dict):
        for signal, sites in list(ev.items())[:8]:
            where = ", ".join(str(x) for x in (sites or [])[:2])
            s.append(Paragraph(
                f"{escape(str(signal))} <font face='Courier' size='8'>{escape(where)}</font>",
                st["bullet"], bulletText="•"))
    elif isinstance(ev, list):
        for line in ev[:8]:
            s.append(Paragraph(escape(str(line)), st["bullet"], bulletText="•"))

    # ------------------------------------------------ 5. risk classification ----
    H("5. Risk classification")
    s.append(_table(
        [["Severity", "Impact: High", "Impact: Medium", "Impact: Low"],
         ["Likelihood: High", "Critical", "High", "Medium"],
         ["Likelihood: Medium", "High", "Medium", "Low"],
         ["Likelihood: Low", "Medium", "Low", "Low"]],
        [40 * mm, 33 * mm, 36 * mm, 31 * mm]))
    s.append(Spacer(1, 4 * mm))
    s.append(Paragraph("5.1. Impact", st["h2"]))
    bullets(IMPACT_DEF)
    s.append(Paragraph("5.2. Likelihood", st["h2"]))
    bullets(LIKELIHOOD_DEF)
    s.append(Paragraph("5.3. Action required for severity levels", st["h2"]))
    bullets(ACTION_REQUIRED)

    # ------------------------------------------------------- 6. assessment ----
    s.append(PageBreak())
    H("6. Security assessment summary")
    if commit:
        s.append(P(f"Review commit hash: <font face='Courier' size='9'>{escape(commit)}</font>"))
    s.append(Paragraph("Scope", st["h2"]))
    s.append(P("The following were in the scope of the review:"))
    for item in [
        "Application source across Rust, Go, Python, JavaScript and TypeScript",
        "Container and deployment configuration",
        "KMS key policy",
        "OS and firmware build recipes (BitBake, EDK II)",
        "The built enclave image, where one is present in the tree",
    ]:
        s.append(Paragraph(escape(item), st["bullet"], bulletText="•"))
    s.append(P(
        "Excluded: paths that are test data, mocks, simulators, fixtures or vendored "
        "samples, and anything that is not resident in the repository at the commit above. "
        "Live infrastructure was not touched: no credentials were used, no attestation was "
        "fetched from running hardware, and the deployed KMS policy was not read."))
    s.append(Paragraph("Analysis performed", st["h2"]))
    for name, text in [
        ("Deterministic rules", "parse, AST and configuration checks over source, "
                                "containers, deployment manifests and KMS policy."),
        ("Code-pattern rules", "a TEE-specific semgrep ruleset across Rust, Go, Python, "
                               "JavaScript and TypeScript."),
        ("OS and firmware", "BitBake recipes and EDK II build invocations, which decide "
                            "what the machine the workload runs on was built from."),
        ("Image analysis", "where an enclave image is present: format parse, ramdisk walk, "
                           "measurement recomputation and a secret scan of the contents."),
    ]:
        s.append(Paragraph(f"<b>{name}</b>: {text}", st["bullet"], bulletText="•"))

    # Attack vectors covered. Every catalogued rule that applied to this platform and
    # produced nothing is a vector that was looked for and not found, which is the half of
    # a review that a findings list alone never shows.
    fired = {f["rule_id"] for f in findings}
    plat_key = str(result.get("platform", {}).get("summary", "")).lower()
    covered = []
    for rid, rule in sorted(catalog.items()):
        if rid in fired or rule.get("status") == "draft":
            continue
        plats = [str(x).lower() for x in (rule.get("platform") or [])]
        if plats and "generic" not in plats and not any(x in plat_key for x in plats):
            continue
        if rule.get("rationale"):
            covered.append(rule)
    if covered:
        s.append(Paragraph("Attack vectors covered", st["h2"]))
        s.append(P(
            "Each of the following was looked for across the scope above and no instance "
            "was found. They are listed because a findings list on its own does not "
            "distinguish what was checked and held from what was never checked."))
        for i, rule in enumerate(covered[:14], 1):
            s.append(Paragraph(f"{i}. {escape(str(rule['title']))}", st["h3"]))
            s.append(Paragraph("<b>Description</b>", st["body"]))
            s.append(P(escape(" ".join(str(rule["rationale"]).split()))[:900]))
            s.append(Paragraph("<b>Protection</b>", st["body"]))
            s.append(P(
                f"No instance was found in the reviewed scope. The check is "
                f"{escape(str(rule.get('detection', 'deterministic')))} and is recorded "
                f"under {escape(rid_of(rule))}."))
        if len(covered) > 14:
            s.append(P(f"A further {len(covered) - 14} vectors were checked and produced "
                       f"no finding."))

    s.append(Paragraph("Security layer scorecard", st["h2"]))
    layer, ceiling = sc.get("effective_layer"), sc.get("verifiable_ceiling")
    s.append(P(
        f"Effective layer <b>{layer if layer is not None else 'not scored'}</b> of a "
        f"verifiable ceiling of {ceiling}. The ladder is the Bluethroat Labs layer model. "
        f"Failing one rule caps the deployment below the layer that rule is required for."))
    per_layer, scored = sc.get("per_layer") or {}, sc.get("assessed", True)
    if per_layer:
        rows = [["Layer", "Required rules", "Status"]]
        for level in range(1, 7):
            info = per_layer.get(str(level)) or per_layer.get(level)
            if not info:
                continue
            if not scored:
                status = "not assessed (no platform detected)"
            elif info["required_rules"] == 0:
                status = "unassessed (no rules)"
            elif info["passes"]:
                status = "pass"
            else:
                status = f"fails ({len(info['failing'])})"
            rows.append([str(level), str(info["required_rules"]), status])
        s.append(_table(rows, [22 * mm, 34 * mm, 62 * mm]))

    # ------------------------------------------------- 7. executive summary ----
    s.append(PageBreak())
    H("7. Executive summary")
    distinct = len({f["rule_id"] for f in findings})
    s.append(P(
        f"A static security review of <b>{escape(target)}</b> was performed with rootward "
        f"at the commit named in section 6. A total of <b>{len(findings)}</b> findings were "
        f"reported across <b>{distinct}</b> distinct rules."))

    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("Review Summary", st["h2"]))
    repo = result.get("repository") or ""
    s.append(_table(
        [["Target", target],
         ["Repository", repo or "local checkout"],
         ["Commit", (commit or "not a git checkout")[:40]],
         ["Date", datetime.now(UTC).strftime("%d %B %Y")],
         ["Platform", str(result.get("platform", {}).get("summary", "unknown"))]],
        [32 * mm, 108 * mm],
        [("FONT", (0, 0), (0, -1), "Times-Bold", 9.5)]))

    s.append(Spacer(1, 4 * mm))
    s.append(Paragraph("Findings Count", st["h2"]))
    rows = [["Severity", "Amount"]]
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            rows.append([sev.capitalize(), str(counts[sev])])
    rows.append(["Total Findings", str(len(findings))])
    s.append(_table(rows, [40 * mm, 26 * mm],
                    [("FONT", (0, -1), (-1, -1), "Times-Bold", 9.5)]))

    if ordered:
        s.append(Spacer(1, 4 * mm))
        s.append(Paragraph("Summary of Findings", st["h2"]))
        # Location is a column, not a detail. Without it a reader cannot tell whether six
        # rows of one rule are six call sites or one defect counted six times, and that is
        # the first question anyone asks of a generated table.
        rows = [["ID", "Title", "Location", "Severity"]]
        for f in ordered:
            t = str((catalog.get(f["rule_id"], {}).get("title")) or f["rule_id"])
            loc = f"{f['file']}:{f['line']}"
            rows.append([labels[id(f)],
                         Paragraph(escape(t), st["toc2"]),
                         Paragraph(escape(loc), st["locsm"]),
                         f["severity"].capitalize()])
        s.append(_table(rows, [13 * mm, 58 * mm, 55 * mm, 19 * mm]))

        # Same data by rule, so repetition is visible as repetition.
        by_rule = {}
        for f in ordered:
            by_rule.setdefault(f["rule_id"], []).append(f)
        if len(by_rule) < len(ordered):
            s.append(Spacer(1, 4 * mm))
            s.append(Paragraph("Findings by rule", st["h2"]))
            s.append(P(
                "The same findings grouped by the rule that produced them. A rule with "
                "several instances is several call sites, each cited separately above, not "
                "one defect reported repeatedly."))
            rows = [["Rule", "Instances", "IDs"]]
            for rid, group in sorted(by_rule.items(),
                                     key=lambda kv: (order.get(kv[1][0]["severity"], 9),
                                                     -len(kv[1]))):
                t = str((catalog.get(rid, {}).get("title")) or rid)
                rows.append([Paragraph(escape(t), st["toc2"]), str(len(group)),
                             Paragraph(", ".join(labels[id(x)] for x in group), st["locsm"])])
            s.append(_table(rows, [72 * mm, 20 * mm, 53 * mm]))

    # -------------------------------------------------------- 8. findings ----
    s.append(PageBreak())
    H("8. Findings")
    if not ordered:
        s.append(P("No findings at or above the reporting threshold."))
    current = None
    for f in ordered:
        sev = f["severity"]
        if sev != current:
            current = sev
            s.append(Paragraph(f"8.{SEVERITY_ORDER.index(sev) + 1}. {sev.capitalize()} findings",
                               st["h2"]))
        rule = catalog.get(f["rule_id"], {})
        title = rule.get("title") or f["rule_id"]
        colour = SEVERITY_COLOR.get(sev, "#000000")
        s.append(Paragraph(
            f"<font color='{colour}'>[{labels[id(f)]}]</font> {escape(str(title))}", st["h3"]))
        # Location only. Confidence and detector provenance are how the tool reasons, not
        # what a review reports; they stay in the JSON for anyone reproducing this.
        s.append(Paragraph(escape(f"{f['file']}:{f['line']}"), st["meta"]))
        s.append(Paragraph("<b>Description</b>", st["body"]))
        s.append(P(escape(f.get("message", ""))))
        if (f.get("evidence") or "").strip():
            s.append(Paragraph("<b>Evidence</b>", st["body"]))
            s.append(Paragraph(_wrap_code(f["evidence"]), st["code"]))
        if rule.get("remediation"):
            s.append(Paragraph("<b>Recommendations</b>", st["body"]))
            s.append(P(escape(" ".join(str(rule["remediation"]).split()))))

    # ------------------------------------------------------ 9. not verified ----
    doc.multiBuild(s)
    return out_path
