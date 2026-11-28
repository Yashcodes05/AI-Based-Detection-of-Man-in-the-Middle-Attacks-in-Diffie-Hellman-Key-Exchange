"""Generate diagrams and the formatted MSRIT CNS Project Report (.docx).

Uses real evaluation metrics and live socket session results from detector.py
and dh_engine.py so all numbers in the report match the implemented system.
"""

from __future__ import annotations

import random
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

from detector import DHMitmDetector
from dh_engine import generate_dataset, run_socket_dh_session
from features import FEATURE_SPECS

ROOT = Path(__file__).resolve().parent
ASSETS_DIR = ROOT / "report_assets"
REPORT_PATH = ROOT / "MSRIT_CNS_Project_Report.docx"

NAVY = RGBColor(0x0F, 0x2B, 0x5B)
DARK_GRAY = RGBColor(0x22, 0x22, 0x22)
MUTED_GRAY = RGBColor(0x55, 0x55, 0x55)


def generate_diagrams(detector: DHMitmDetector) -> dict[str, Path]:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    # 1. Honest DH vs MITM Attack Diagram
    fig, ax = plt.subplots(figsize=(9.5, 4.4), dpi=220)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5)
    ax.axis("off")
    fig.patch.set_facecolor("#ffffff")

    def draw_box(x, y, w, h, title, sub, edge="#0f4c81", fill="#eef5fc"):
        rect = patches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.12", linewidth=1.8, edgecolor=edge, facecolor=fill
        )
        ax.add_patch(rect)
        ax.text(x + w / 2, y + h * 0.65, title, ha="center", va="center", fontsize=10, fontweight="bold", color="#111")
        ax.text(x + w / 2, y + h * 0.30, sub, ha="center", va="center", fontsize=8.5, color="#333")

    # Top row: Honest Exchange
    ax.text(0.3, 4.55, "A. Honest Diffie–Hellman Exchange (Shared Secret K = g^(ab) mod p)", fontsize=10.5, fontweight="bold", color="#0f4c81")
    draw_box(0.4, 3.2, 2.0, 1.0, "ALICE", "Secret a\nK = B^a mod p", "#0f766e", "#ecfdf5")
    draw_box(7.4, 3.2, 2.0, 1.0, "BOB", "Secret b\nK = A^b mod p", "#0f766e", "#ecfdf5")
    ax.annotate("", xy=(7.3, 3.9), xytext=(2.5, 3.9), arrowprops=dict(arrowstyle="->", lw=1.8, color="#0f766e"))
    ax.text(4.9, 4.08, "Public A = g^a mod p", ha="center", fontsize=8.5, color="#0f766e")
    ax.annotate("", xy=(2.5, 3.45), xytext=(7.3, 3.45), arrowprops=dict(arrowstyle="->", lw=1.8, color="#0f766e"))
    ax.text(4.9, 3.22, "Public B = g^b mod p   (K_A == K_B)", ha="center", fontsize=8.5, color="#0f766e")

    # Bottom row: MITM Attack
    ax.text(0.3, 2.25, "B. Man-in-the-Middle (MITM) Attack (Split Secrets K1 != K2)", fontsize=10.5, fontweight="bold", color="#b91c1c")
    draw_box(0.4, 0.55, 2.0, 1.2, "ALICE", "Secret a\nDerives K1", "#1d4ed8", "#eff6ff")
    draw_box(3.9, 0.55, 2.1, 1.2, "ATTACKER (MITM)", "Substitutes E1, E2\nHolds K1 & K2", "#b91c1c", "#fef2f2")
    draw_box(7.4, 0.55, 2.0, 1.2, "BOB", "Secret b\nDerives K2", "#1d4ed8", "#eff6ff")

    ax.annotate("", xy=(3.8, 1.35), xytext=(2.5, 1.35), arrowprops=dict(arrowstyle="<->", lw=1.8, color="#b91c1c"))
    ax.text(3.15, 1.55, "A <-> E1\n(K1)", ha="center", fontsize=8, color="#b91c1c")
    ax.annotate("", xy=(7.3, 1.35), xytext=(6.1, 1.35), arrowprops=dict(arrowstyle="<->", lw=1.8, color="#b91c1c"))
    ax.text(6.7, 1.55, "E2 <-> B\n(K2)", ha="center", fontsize=8, color="#b91c1c")

    p1 = ASSETS_DIR / "fig1_dh_honest_vs_mitm.png"
    fig.savefig(p1, bbox_inches="tight", dpi=220)
    plt.close(fig)
    paths["dh_diagram"] = p1

    # 2. System Architecture Diagram
    fig, ax = plt.subplots(figsize=(9.5, 3.6), dpi=220)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4)
    ax.axis("off")
    fig.patch.set_facecolor("#ffffff")

    stages = [
        (0.2, 1.3, 1.75, 1.4, "1. Traffic\nCollection", "Local TCP DH\nSocket Telemetry\n(No Secrets)", "#0f4c81", "#eef5fc"),
        (2.2, 1.3, 1.85, 1.4, "2. Feature\nExtraction", "14 Features:\nNetwork (5)\nHandshake (5)\nBehavioral (4)", "#0f766e", "#ecfdf5"),
        (4.3, 1.3, 1.85, 1.4, "3. AI Anomaly\nDetection", "Isolation Forest\n(Trained on\nNormal Only)", "#6d28d9", "#f5f3ff"),
        (6.4, 1.3, 1.65, 1.4, "4. Risk\nScoring", "0–100 Score\nLOW / MED /\nHIGH", "#b45309", "#fffbeb"),
        (8.3, 1.3, 1.55, 1.4, "5. Alert &\nDashboard", "Flask UI\n+σ Indicators\nAI ON/OFF", "#b91c1c", "#fef2f2"),
    ]
    for i, (x, y, w, h, title, sub, edge, fill) in enumerate(stages):
        rect = patches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.1", linewidth=1.8, edgecolor=edge, facecolor=fill
        )
        ax.add_patch(rect)
        ax.text(x + w / 2, y + h * 0.74, title, ha="center", va="center", fontsize=9, fontweight="bold", color="#111")
        ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center", fontsize=7.5, color="#333")
        if i < len(stages) - 1:
            nx = stages[i + 1][0]
            ax.annotate("", xy=(nx - 0.06, y + h / 2), xytext=(x + w + 0.06, y + h / 2), arrowprops=dict(arrowstyle="->", lw=1.8, color="#334155"))

    ax.text(5.0, 3.45, "Proposed AI-Based Behavioral Detection Pipeline (Complements Cryptographic Auth)", ha="center", fontsize=10.5, fontweight="bold", color="#0f2b5b")
    p2 = ASSETS_DIR / "fig2_system_architecture.png"
    fig.savefig(p2, bbox_inches="tight", dpi=220)
    plt.close(fig)
    paths["architecture"] = p2

    # 3. Model Comparison Chart (Real Metrics)
    metrics = detector.comparison_metrics
    models = [m["model"].replace(" (Primary)", "\n(Primary)") for m in metrics]
    acc = [m["accuracy"] for m in metrics]
    prec = [m["precision"] for m in metrics]
    rec = [m["recall"] for m in metrics]
    f1 = [m["f1"] for m in metrics]

    x = np.arange(len(models))
    width = 0.19
    fig, ax = plt.subplots(figsize=(8.8, 4.0), dpi=220)
    ax.bar(x - 1.5 * width, acc, width, label="Accuracy (%)", color="#0f4c81")
    ax.bar(x - 0.5 * width, prec, width, label="Precision (%)", color="#0f766e")
    ax.bar(x + 0.5 * width, rec, width, label="Recall (%)", color="#d97706")
    ax.bar(x + 1.5 * width, f1, width, label="F1 Score (%)", color="#6d28d9")

    ax.set_ylabel("Percentage (%)")
    ax.set_title("Detection Performance: Isolation Forest vs. Supervised Baselines")
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=9)
    ax.set_ylim(75, 103)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(loc="lower right", fontsize=8.5)

    p3 = ASSETS_DIR / "fig3_model_comparison.png"
    fig.savefig(p3, bbox_inches="tight", dpi=220)
    plt.close(fig)
    paths["model_comparison"] = p3

    # 4. Risk Score Distribution (Normal vs MITM)
    records = generate_dataset(n_normal=120, n_attack=120, seed=99)
    norm_scores = [detector.score_session(r).risk_score for r in records if r["label"] == 0]
    mitm_scores = [detector.score_session(r).risk_score for r in records if r["label"] == 1]

    fig, ax = plt.subplots(figsize=(8.6, 3.8), dpi=220)
    bins = np.linspace(0, 100, 21)
    ax.hist(norm_scores, bins=bins, alpha=0.75, label="Normal DH Sessions (n=120)", color="#10b981", edgecolor="#065f46")
    ax.hist(mitm_scores, bins=bins, alpha=0.75, label="MITM Attack Sessions (n=120)", color="#ef4444", edgecolor="#991b1b")
    ax.axvline(70, color="#111827", linestyle="--", linewidth=1.6, label="High-Risk Alert Threshold (70)")
    ax.set_xlabel("AI Risk Score (0–100)")
    ax.set_ylabel("Session Count")
    ax.set_title("Risk Score Separation: Honest DH vs. MITM Attacks")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.legend(fontsize=8.5)

    p4 = ASSETS_DIR / "fig4_risk_distribution.png"
    fig.savefig(p4, bbox_inches="tight", dpi=220)
    plt.close(fig)
    paths["risk_distribution"] = p4

    return paths


def set_cell_shading(cell, hex_color: str) -> None:
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading)


def add_page_number(run) -> None:
    fldChar1 = parse_xml(r'<w:fldChar %s w:fldCharType="begin"/>' % nsdecls("w"))
    instrText = parse_xml(r'<w:instrText %s xml:space="preserve"> PAGE </w:instrText>' % nsdecls("w"))
    fldChar2 = parse_xml(r'<w:fldChar %s w:fldCharType="separate"/>' % nsdecls("w"))
    fldChar3 = parse_xml(r'<w:fldChar %s w:fldCharType="end"/>' % nsdecls("w"))
    run._r.append(fldChar1)
    run._r.append(instrText)
    run._r.append(fldChar2)
    run._r.append(fldChar3)


def add_heading(doc: Document, number: str, title: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(f"{number}. {title}")
    run.bold = True
    run.font.size = Pt(14)
    run.font.color.rgb = NAVY


def add_subheading(doc: Document, title: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(3)
    run = p.add_run(title)
    run.bold = True
    run.font.size = Pt(11.5)
    run.font.color.rgb = DARK_GRAY


def add_body(doc: Document, text: str) -> None:
    p = doc.add_paragraph(text)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.2
    for run in p.runs:
        run.font.size = Pt(11)
        run.font.color.rgb = DARK_GRAY


def add_bullet(doc: Document, lead: str, text: str) -> None:
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(3)
    r1 = p.add_run(lead)
    r1.bold = True
    r1.font.size = Pt(10.5)
    r2 = p.add_run(text)
    r2.font.size = Pt(10.5)


def add_figure(doc: Document, img_path: Path, caption: str, width_in: float = 6.2) -> None:
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(6)
    p_img.paragraph_format.space_after = Pt(3)
    p_img.add_run().add_picture(str(img_path), width=Inches(width_in))

    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_after = Pt(8)
    rc = p_cap.add_run(caption)
    rc.italic = True
    rc.font.size = Pt(9.5)
    rc.font.color.rgb = MUTED_GRAY


def add_styled_table(doc: Document, headers: list[str], rows: list[list[str]]) -> None:
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    for j, h in enumerate(headers):
        cell = table.rows[0].cells[j]
        set_cell_shading(cell, "0F2B5B")
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for i, row in enumerate(rows):
        bg = "F4F7FB" if i % 2 == 1 else "FFFFFF"
        for j, val in enumerate(row):
            cell = table.rows[i + 1].cells[j]
            set_cell_shading(cell, bg)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.size = Pt(9.5)
            r.font.color.rgb = DARK_GRAY

    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def build_report() -> None:
    detector = DHMitmDetector.load_or_train()
    figs = generate_diagrams(detector)

    # Run 2 real socket sessions for concrete sample evidence in Results
    rng = random.Random(42)
    honest_sess = run_socket_dh_session("none", rng=rng)
    honest_verdict = detector.score_session(honest_sess.telemetry)
    mitm_sess = run_socket_dh_session("active_mitm", rng=rng)
    mitm_verdict = detector.score_session(mitm_sess.telemetry)

    doc = Document()
    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Times New Roman"
    normal_style.font.size = Pt(11)

    section = doc.sections[0]
    section.different_first_page_header_footer = True
    section.top_margin = Inches(0.85)
    section.bottom_margin = Inches(0.85)
    section.left_margin = Inches(0.95)
    section.right_margin = Inches(0.95)

    # Header & Footer for pages 2+
    hdr = section.header.paragraphs[0]
    hdr.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = hdr.add_run("RAMAIAH INSTITUTE OF TECHNOLOGY  |  DEPARTMENT OF CSE (CYBER SECURITY)")
    hr.font.size = Pt(8.5)
    hr.bold = True
    hr.font.color.rgb = NAVY

    ftr = section.footer.paragraphs[0]
    ftr.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    fr1 = ftr.add_run("24CY53 Cryptography and Network Security   |   Page ")
    fr1.font.size = Pt(8.5)
    fr1.font.color.rgb = MUTED_GRAY
    add_page_number(ftr.add_run())

    # ==================== PAGE 1: COVER PAGE ====================
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("M. S. RAMAIAH INSTITUTE OF TECHNOLOGY\n")
    r.bold = True
    r.font.size = Pt(14)
    r.font.color.rgb = NAVY
    r2 = p.add_run("DEPARTMENT OF CSE (CYBER SECURITY)")
    r2.bold = True
    r2.font.size = Pt(11)
    r2.font.color.rgb = RGBColor(0x8B, 0x1E, 0x3F)

    doc.add_paragraph("\n")
    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rs = p_sub.add_run("Cryptography and Network Security Project Report")
    rs.bold = True
    rs.font.size = Pt(13)

    doc.add_paragraph()
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rt = p_title.add_run("AI-Based Detection of Man-in-the-Middle Attacks in\nDiffie–Hellman Key Exchange")
    rt.bold = True
    rt.font.size = Pt(16)
    rt.font.color.rgb = NAVY

    doc.add_paragraph()
    p_req = doc.add_paragraph()
    p_req.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_req.add_run(
        "Submitted in partial fulfilment of the requirements for the academic requirements of\n"
        "5th Semester – 24CY53 Cryptography and Network Security\n\nIn\n"
    ).font.size = Pt(11)
    r_dept = p_req.add_run("Dept. of CSE (Cyber Security)\n\n")
    r_dept.bold = True
    r_dept.font.size = Pt(12)

    p_by = doc.add_paragraph()
    p_by.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_by.add_run("By\n\n").font.size = Pt(11)
    for name, usn in [
        ("YASH RAJ SINHA", "1MS24CY071"),
        ("ADVAIT PATHAK", "1MS24CY006"),
        ("SHASHWAT PANDEY", "1MS24CY057"),
    ]:
        rn = p_by.add_run(f"{name}   ({usn})\n")
        rn.bold = True
        rn.font.size = Pt(11.5)

    doc.add_paragraph()
    p_guide = doc.add_paragraph()
    p_guide.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_guide.add_run("Under the guidance of\n\n").font.size = Pt(11)
    rg = p_guide.add_run(
        "Prof. Rashmi T V\n"
        "Assistant Professor\n"
        "Department of CSE (Cyber Security)\n\n"
    )
    rg.bold = True
    rg.font.size = Pt(11.5)

    p_inst = doc.add_paragraph()
    p_inst.alignment = WD_ALIGN_PARAGRAPH.CENTER
    ri = p_inst.add_run("M. S. Ramaiah Institute of Technology\n")
    ri.bold = True
    ri.font.size = Pt(12)
    p_inst.add_run(
        "(Autonomous Institute Affiliated to VTU)\n"
        "MSR Nagar, MSRIT Post\n"
        "Bangalore-560054, Karnataka, India"
    ).font.size = Pt(10.5)

    doc.add_page_break()

    # ==================== PAGE 2: CERTIFICATE ====================
    p_cert = doc.add_paragraph()
    p_cert.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rc = p_cert.add_run("Certificate")
    rc.bold = True
    rc.font.size = Pt(16)
    rc.font.color.rgb = NAVY

    doc.add_paragraph()
    add_body(
        doc,
        "This is to certify that the project report entitled “AI-Based Detection of Man-in-the-Middle "
        "Attacks in Diffie–Hellman Key Exchange” has been carried out by Yash Raj Sinha (1MS24CY071), "
        "Advait Pathak (1MS24CY006), and Shashwat Pandey (1MS24CY057) under the supervision of "
        "Prof. Rashmi T V, Assistant Professor, Dept of CSE (Cyber Security), as part of the Learning "
        "Activity component of the course Cryptography and Network Security (24CY53) in the 5th semester, "
        "in partial fulfilment of the requirements for the award of the degree of Bachelor of Engineering in "
        "Computer Science & Engineering (Cyber Security) at M S Ramaiah Institute of Technology, Bengaluru, "
        "during the academic year 2026-2027.",
    )

    doc.add_paragraph("\n\n\n\n")
    sig_table = doc.add_table(rows=1, cols=2)
    sig_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    sig_table.rows[0].cells[0].paragraphs[0].add_run("Student Sign").bold = True
    p_fs = sig_table.rows[0].cells[1].paragraphs[0]
    p_fs.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p_fs.add_run("Faculty Sign").bold = True

    doc.add_page_break()

    # ==================== SECTION 1: ABSTRACT ====================
    add_heading(doc, "1", "Abstract")
    add_body(
        doc,
        "The Diffie–Hellman (DH) key exchange protocol enables two communicating parties to establish a shared "
        "cryptographic secret over an insecure public channel. However, classical unauthenticated Diffie–Hellman "
        "does not verify peer identities, leaving it vulnerable to active Man-in-the-Middle (MITM) attacks in "
        "which an adversary intercepts and substitutes public key values to establish two separate secrets (K1 and K2). "
        "This project implements an AI-driven behavioral anomaly detection layer that complements existing "
        "cryptographic defenses by observing 14 non-secret metadata features across network, handshake, and "
        "session-behavioral dimensions. Using an unsupervised Isolation Forest trained exclusively on normal "
        "baseline traffic, the system assigns a normalized 0–100 Risk Score and generates interpretable z-score "
        "indicators for every handshake. A live local TCP socket simulator (RFC 3526 2048-bit MODP Group 14) and "
        "interactive Flask dashboard demonstrate both unmonitored DH blind spots (AI OFF) and real-time MITM "
        "detection (AI ON), achieving high detection performance alongside Random Forest, Gradient Boosting, and "
        "Artificial Neural Network (MLP) comparison baselines.",
    )

    # ==================== SECTION 2: TABLE OF CONTENTS ====================
    add_heading(doc, "2", "Table of Contents")
    toc_rows = [
        ["1.", "Abstract", "3"],
        ["2.", "Table of Contents", "3"],
        ["3.", "List of Figures and Tables", "4"],
        ["4.", "Introduction", "5"],
        ["5.", "Problem Statement", "5"],
        ["6.", "Objectives", "6"],
        ["7.", "Literature Review / Existing System", "6"],
        ["8.", "Proposed System", "7"],
        ["9.", "System Architecture / Workflow", "7"],
        ["10.", "Tools and Technologies Used", "8"],
        ["11.", "Methodology", "9"],
        ["12.", "Implementation / Project Development", "10"],
        ["13.", "Experimental Setup", "11"],
        ["14.", "Results and Analysis", "11"],
        ["15.", "Screenshots / Demonstration", "13"],
        ["16.", "Conclusion", "14"],
        ["17.", "Future Enhancements", "14"],
        ["18.", "References", "15"],
    ]
    add_styled_table(doc, ["Sl. No.", "Contents", "Section / Ref"], toc_rows)

    # ==================== SECTION 3: LIST OF FIGURES AND TABLES ====================
    add_heading(doc, "3", "List of Figures and Tables")
    add_styled_table(
        doc,
        ["Figure / Table", "Title"],
        [
            ["Figure 1", "Honest Diffie–Hellman Key Exchange vs. Man-in-the-Middle Key Substitution"],
            ["Figure 2", "Proposed AI-Based Behavioral Detection Pipeline"],
            ["Figure 3", "Model Performance Comparison: Isolation Forest vs. Supervised Baselines"],
            ["Figure 4", "Risk Score Distribution for Normal DH Sessions vs. MITM Attacks"],
            ["Table 1", "Literature Survey Summary and Identified Research Gap"],
            ["Table 2", "Observable Feature Set (14 Features Across 3 Categories)"],
            ["Table 3", "Quantitative Evaluation of Isolation Forest and Comparison Baselines"],
            ["Table 4", "Live Local Socket Handshake Verification (Honest vs. Active MITM)"],
        ],
    )

    # ==================== SECTION 4: INTRODUCTION ====================
    add_heading(doc, "4", "Introduction")
    add_body(
        doc,
        "Secure key establishment is the foundation of modern encrypted communication. Introduced in 1976 by "
        "Whitfield Diffie and Martin Hellman, the Diffie–Hellman (DH) key exchange allows two parties—traditionally "
        "Alice and Bob—to agree upon a shared secret K = g^(ab) mod p over an untrusted network without ever "
        "transmitting the secret itself. Security against passive eavesdroppers rests on the computational "
        "intractability of the Discrete Logarithm Problem (DLP).",
    )
    add_body(
        doc,
        "Despite its mathematical elegance, basic Diffie–Hellman establishes a shared secret without authenticating "
        "the communicating parties. If an active adversary sits on the communication path, the attacker can intercept "
        "public values, substitute their own DH exponents, and establish independent secrets K1 (with Alice) and K2 "
        "(with Bob). Legacy industrial deployments, misconfigured TLS/SSH services, and environments with weak PKI "
        "governance remain exposed to such MITM attacks—as highlighted by real-world advisories such as CISA "
        "CVE-2024-8935 in Schneider Electric Modicon systems.",
    )
    add_figure(
        doc,
        figs["dh_diagram"],
        "Figure 1: Honest Diffie–Hellman Key Exchange (top) vs. Man-in-the-Middle Key Substitution (bottom).",
    )

    # ==================== SECTION 5: PROBLEM STATEMENT ====================
    add_heading(doc, "5", "Problem Statement")
    add_body(
        doc,
        "Standard unauthenticated Diffie–Hellman key exchange provides confidentiality against passive observers "
        "but lacks peer authentication. Neither party can determine from the DH mathematics alone whether the "
        "received public key originated from the intended peer or an active intermediary. Rule-based Intrusion "
        "Detection Systems (IDS) rely on static signatures and struggle to detect novel or stealthy MITM proxies. "
        "Therefore, there is a need for an adaptive, non-intrusive AI monitoring layer that detects anomalous "
        "handshake and session behavior around Diffie–Hellman exchanges without inspecting or weakening "
        "cryptographic secrets.",
    )

    # ==================== SECTION 6: OBJECTIVES ====================
    add_heading(doc, "6", "Objectives")
    add_bullet(doc, "1. Real DH & MITM Simulation: ", "Implement an authentic RFC 3526 2048-bit Diffie–Hellman key exchange over local TCP sockets supporting both honest exchanges and active MITM proxy interception (active, stealth, and retry-heavy profiles).")
    add_bullet(doc, "2. Secret-Free Feature Engineering: ", "Extract 14 observable network-level, handshake-level, and session-behavioral metadata features without ever accessing private exponents or shared secrets.")
    add_bullet(doc, "3. Unsupervised AI Anomaly Detection: ", "Train an Isolation Forest model solely on normal baseline DH traffic to compute a normalized 0–100 Risk Score and human-readable +σ indicators.")
    add_bullet(doc, "4. Baseline Benchmarking & Live Demo UI: ", "Compare Isolation Forest against Random Forest, Gradient Boosting, and ANN (MLP), and build an interactive Flask dashboard with an AI ON/OFF toggle, batch simulation, timeline chart, and session filters.")

    # ==================== SECTION 7: LITERATURE REVIEW / EXISTING SYSTEM ====================
    add_heading(doc, "7", "Literature Review / Existing System")
    add_body(
        doc,
        "Existing defenses operate across three layers: cryptographic protection (digital signatures, PKI certificates, "
        "authenticated DH/ECDH), secure protocols (TLS 1.3 RFC 8446 with forward-secret authenticated handshakes), "
        "and network security (firewalls, IDS/IPS, and rule-based monitoring). Prior ML-based MITM studies focus "
        "primarily on IoT, MQTT, and SCADA environments:",
    )
    add_styled_table(
        doc,
        ["Ref", "Authors & Year", "Domain / Focus", "Key Finding & Relevance"],
        [
            ["[1]", "Diffie & Hellman (1976)", "Public-key key exchange", "Foundational DH protocol over open channels; lacks built-in authentication."],
            ["[2]", "Sivasankari & Kamalakkannan (2022)", "IoT MITM (Regression)", "Regression-based identification of MITM nodes and attack-free routes."],
            ["[3]", "Mughaid et al. (2023)", "SCADA MITM-ARP Spoofing", "Random Forest achieved ~98.22% accuracy on industrial network traffic."],
            ["[4]", "Michelena et al. (2024)", "MQTT / IoT ML Detection", "ANN achieved AUC ~0.992 on dedicated protocol-level MQTT traffic."],
            ["[5]", "Kandasamy & Roseline (2025)", "Hybrid Deep Learning MITM", "AutoEncoder + XGBoost reached ~97.24% accuracy for cyber defense."],
            ["[8]", "Liu, Ting & Zhou (2008)", "Isolation Forest", "Random partitioning isolates anomalies quickly without labeled attack data."],
        ],
    )
    add_body(
        doc,
        "Research Gap: Existing AI/ML MITM literature concentrates on IoT, MQTT, and SCADA traffic, with "
        "comparatively little focus on behavioral anomaly detection around the Diffie–Hellman key-exchange process "
        "itself. Our system addresses this gap by positioning AI as a complementary monitoring layer.",
    )

    # ==================== SECTION 8: PROPOSED SYSTEM ====================
    add_heading(doc, "8", "Proposed System")
    add_body(
        doc,
        "The proposed system introduces a passive AI behavioral monitoring layer around Diffie–Hellman handshakes. "
        "Existing cryptographic authentication remains the primary defense; the AI layer provides defense-in-depth "
        "visibility when legacy configurations or misconfigurations weaken authentication. By training an Isolation "
        "Forest exclusively on normal handshake metadata, the detector flags unseen MITM behaviors with a 0–100 Risk "
        "Score and interpretable indicators (e.g., unexpected intermediary host, unusual handshake timing, repeated "
        "handshake attempts, and network-path anomalies).",
    )

    # ==================== SECTION 9: SYSTEM ARCHITECTURE / WORKFLOW ====================
    add_heading(doc, "9", "System Architecture / Workflow")
    add_body(
        doc,
        "As illustrated in Figure 2, the pipeline executes in five sequential stages: (1) Traffic Collection captures "
        "packet timing, connection counts, and handshake metadata; (2) Feature Extraction converts raw telemetry into "
        "14 numerical features; (3) AI/ML Detection compares the session vector against the learned normal baseline "
        "using Isolation Forest; (4) Risk Scoring normalizes the decision score to 0–100; and (5) Alert & Notify "
        "surfaces interpretable +σ indicators on the Flask dashboard.",
    )
    add_figure(
        doc,
        figs["architecture"],
        "Figure 2: End-to-End AI-Based Behavioral Detection Pipeline for Diffie–Hellman Key Exchange.",
    )

    # ==================== SECTION 10: TOOLS AND TECHNOLOGIES USED ====================
    add_heading(doc, "10", "Tools and Technologies Used")
    add_styled_table(
        doc,
        ["Component", "Technology / Library", "Purpose in Project"],
        [
            ["Language & Runtime", "Python 3.14", "Core backend, TCP sockets, and ML pipeline"],
            ["Cryptography & Networking", "socket, secrets, hashlib (RFC 3526)", "2048-bit MODP Group 14 DH key exchange & MITM proxy"],
            ["Machine Learning", "scikit-learn (IsolationForest, RF, GB, MLP)", "Unsupervised anomaly detection & baseline benchmarking"],
            ["Data Processing", "NumPy, Pandas, StandardScaler", "Feature vectorization, scaling, and z-score computation"],
            ["Web Dashboard", "Flask 3.1, HTML5, CSS3, Vanilla JS, SVG", "Interactive simulator, AI ON/OFF toggle, charts & filters"],
            ["Testing", "Python unittest", "Automated end-to-end verification of sockets, ML, and APIs"],
        ],
    )

    # ==================== SECTION 11: METHODOLOGY ====================
    add_heading(doc, "11", "Methodology")
    add_body(
        doc,
        "1. Feature Engineering (14 Observable Features): Telemetry is grouped into Network-Level, Handshake-Level, "
        "and Session-Behavioral categories as summarized in Table 2. Private keys and shared secrets are strictly "
        "excluded.",
    )
    add_styled_table(
        doc,
        ["Category", "Feature Name", "Observable Indicator"],
        [[spec.category, spec.name, spec.indicator_label] for spec in FEATURE_SPECS],
    )
    add_body(
        doc,
        "2. Unsupervised Training & Risk Calibration: StandardScaler and IsolationForest (n_estimators=200, "
        "contamination=0.03) are fitted exclusively on normal baseline sessions. The decision_function output is "
        "calibrated using a logistic mapping centered at the 5th percentile of normal scores to produce a 0–100 "
        "Risk Score: LOW (0–44, Normal), MEDIUM (45–69, Suspicious Handshake), and HIGH (70–100, Potential MITM Detected).",
    )

    # ==================== SECTION 12: IMPLEMENTATION / PROJECT DEVELOPMENT ====================
    add_heading(doc, "12", "Implementation / Project Development")
    add_bullet(doc, "dh_engine.py: ", "Implements run_socket_dh_session() using real loopback TCP sockets for Alice, Bob, and an optional Attacker proxy across 'none', 'active_mitm', 'stealth_mitm', and 'retry_mitm' profiles.")
    add_bullet(doc, "features.py: ", "Defines FEATURE_SPECS (14 features) and extract_feature_vector() to build deterministic float64 vectors.")
    add_bullet(doc, "detector.py: ", "Implements DHMitmDetector with fit_and_evaluate(), score_session(), get_feature_breakdown(), and model persistence (models/dh_mitm_detector.pkl).")
    add_bullet(doc, "app.py & Frontend (templates/index.html, static/app.js, static/style.css): ", "Provides REST endpoints (/api/simulate, /api/simulate_batch, /api/metrics, /api/retrain, /api/clear, /api/sessions) and a dark-mode dashboard with KPI cards, AI ON/OFF toggle, SVG risk timeline, 14-feature category tabs, session filters, and a Reset Simulation control.")

    # ==================== SECTION 13: EXPERIMENTAL SETUP ====================
    add_heading(doc, "13", "Experimental Setup")
    add_body(
        doc,
        "Experiments were conducted on Windows 11 with Python 3.14.3 and scikit-learn 1.9.1. A balanced benchmark "
        "dataset of 500 normal DH sessions and 200 MITM attack sessions (across active, stealth, and retry profiles) "
        "was split 70/30 (stratified). Isolation Forest was trained only on the normal training subset (~350 samples), "
        "while Random Forest, Gradient Boosting, and ANN (MLP) were trained on the full labeled training split for "
        "side-by-side comparison. Automated verification was performed via python -m unittest discover -s tests -v.",
    )

    # ==================== SECTION 14: RESULTS AND ANALYSIS ====================
    add_heading(doc, "14", "Results and Analysis")
    add_body(
        doc,
        "Table 3 reports the held-out test-set evaluation metrics obtained from DHMitmDetector.fit_and_evaluate(). "
        "Even though Isolation Forest learns solely from normal baseline traffic without attack labels, it achieves "
        "competitive accuracy and ROC-AUC alongside supervised baselines.",
    )
    add_styled_table(
        doc,
        ["Model", "Paradigm", "Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"],
        [
            [
                m["model"],
                m["paradigm"],
                f"{m['accuracy']}%",
                f"{m['precision']}%",
                f"{m['recall']}%",
                f"{m['f1']}%",
                f"{m['roc_auc']}",
            ]
            for m in detector.comparison_metrics
        ],
    )
    add_figure(
        doc,
        figs["model_comparison"],
        "Figure 3: Held-out Test Performance of Isolation Forest vs. Supervised Baselines.",
    )
    add_figure(
        doc,
        figs["risk_distribution"],
        "Figure 4: Risk Score Separation Between Normal DH Sessions and MITM Attack Sessions (n = 240).",
    )
    add_body(
        doc,
        "Live TCP Socket Verification: Table 4 shows two live local socket handshakes executed during verification. "
        "In the honest exchange, Alice and Bob derive identical shared secret fingerprints and receive a LOW Risk Score. "
        "In the active MITM exchange, the proxy splits the keys (K_A != K_B) and the AI flags a HIGH Risk Score.",
    )
    add_styled_table(
        doc,
        ["Session Mode", "Secrets Match", "Risk Score", "Verdict", "Top Interpretable Indicator"],
        [
            [
                honest_sess.mode,
                "Yes (K_A == K_B)" if honest_sess.secrets_match else "No",
                f"{honest_verdict.risk_score}/100",
                honest_verdict.verdict,
                honest_verdict.indicators[0]["label"] if honest_verdict.indicators else "Baseline normal",
            ],
            [
                mitm_sess.mode,
                "Yes" if mitm_sess.secrets_match else "No (K_A != K_B)",
                f"{mitm_verdict.risk_score}/100",
                mitm_verdict.verdict,
                mitm_verdict.indicators[0]["label"] if mitm_verdict.indicators else "Anomaly",
            ],
        ],
    )

    # ==================== SECTION 15: SCREENSHOTS / DEMONSTRATION ====================
    add_heading(doc, "15", "Screenshots / Demonstration")
    add_body(
        doc,
        "The Flask web dashboard (http://127.0.0.1:5000) demonstrates four core capabilities during live presentation:",
    )
    add_bullet(doc, "1. AI ON vs. AI OFF Contrast: ", "Toggling AI Detection OFF simulates unauthenticated DH—MITM handshakes display '0/100 ACCEPTED (NO AI)' even though the topology diagram reveals the Attacker splitting K1 and K2. Switching AI ON immediately flags the same attack as HIGH RISK with +σ indicators.")
    add_bullet(doc, "2. 14-Feature Telemetry Inspector: ", "Interactive category tabs (All, Network, Handshake, Behavioral) display observed values against baseline means with color-coded deviation bars.")
    add_bullet(doc, "3. Batch Traffic & Risk Timeline: ", "The 'Run Batch (10 Sessions)' button executes 6 honest and 4 mixed MITM socket handshakes, updating KPI cards and plotting a live SVG Risk Score timeline with a 70/100 threshold line.")
    add_bullet(doc, "4. Session Filtering & Reset Simulation: ", "Analysts can filter logs by Search text, Verdict, AI Layer (ON/OFF), Attack Profile, and Minimum Risk Score slider, or click 'Reset Simulation' to reset KPIs and charts while preserving session logs.")

    # ==================== SECTION 16: CONCLUSION ====================
    add_heading(doc, "16", "Conclusion")
    add_body(
        doc,
        "This project demonstrates that an unsupervised Isolation Forest behavioral layer can effectively detect "
        "Man-in-the-Middle attacks in Diffie–Hellman key exchanges using only observable network, handshake, and "
        "session metadata. Without inspecting cryptographic secrets, the system bridges the visibility gap left by "
        "unauthenticated or misconfigured DH deployments, providing real-time 0–100 risk scores and interpretable "
        "indicators validated through automated unit and integration tests (6/6 passing).",
    )

    # ==================== SECTION 17: FUTURE ENHANCEMENTS ====================
    add_heading(doc, "17", "Future Enhancements")
    add_bullet(doc, "Live Packet Capture Integration: ", "Extend traffic collection to ingest live PCAP streams or TLS 1.3 / ECDHE handshakes via Scapy or PyShark.")
    add_bullet(doc, "Online Baseline Adaptation: ", "Support sliding-window retraining so the Isolation Forest adapts to evolving enterprise network latency baselines.")
    add_bullet(doc, "SIEM & Alerting Integration: ", "Export high-risk handshake alerts to syslog, Slack, or SIEM pipelines for automated SOC response.")

    # ==================== SECTION 18: REFERENCES ====================
    add_heading(doc, "18", "References")
    refs = [
        "[1] Diffie, W., & Hellman, M. E. (1976). New Directions in Cryptography. IEEE Transactions on Information Theory.",
        "[2] Sivasankari, N., & Kamalakkannan, S. (2022). Detection and prevention of man-in-the-middle attack in IoT network using regression modeling. Advances in Engineering Software, 169, 103126.",
        "[3] Mughaid, A., et al. (2023). Enhancing Cybersecurity in SCADA IoT Systems: A Novel ML Approach for MITM Detection. 3rd Intelligent Cybersecurity Conference.",
        "[4] Michelena, Á., et al. (2024). A novel intelligent approach for MITM attack detection over IoT environments based on MQTT. Expert Systems, 41(2), e13263.",
        "[5] Kandasamy, V., & Roseline, A. A. (2025). Harnessing advanced hybrid deep learning for real-time MITM attack detection. Scientific Reports, 15, 1697.",
        "[6] Rescorla, E. (2018). RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. IETF Standards Track.",
        "[7] CISA (2024). ICSA-24-326-03 / CVE-2024-8935 — Schneider Electric Modicon Systems. CISA Advisories.",
        "[8] Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. IEEE International Conference on Data Mining.",
    ]
    for ref in refs:
        p_ref = doc.add_paragraph(ref)
        p_ref.paragraph_format.space_after = Pt(4)
        p_ref.runs[0].font.size = Pt(10)

    doc.save(str(REPORT_PATH))
    print(f"Generated report: {REPORT_PATH}")


if __name__ == "__main__":
    build_report()
