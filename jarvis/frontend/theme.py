"""Centralized visual language for the native JARVIS desktop."""

# Qt stylesheet declarations are intentionally kept readable as CSS lines.
# ruff: noqa: E501

from __future__ import annotations

COLORS = {
    "background": "#050A0F",
    "surface": "#090F15",
    "surface_raised": "#0C131A",
    "surface_high": "#101820",
    "border": "#1B2A36",
    "border_active": "#28536D",
    "text": "#E6F0F7",
    "muted": "#8EA4B3",
    "cyan": "#24A8FF",
    "cyan_bright": "#35C2FF",
    "success": "#31D17C",
    "attention": "#EAAA27",
    "danger": "#F05D65",
    "violet": "#7868F5",
}

SPACING = {"xs": 6, "sm": 10, "md": 16, "lg": 24, "xl": 32}
RADIUS = {"sm": 6, "md": 10, "lg": 14}


def desktop_stylesheet() -> str:
    c = COLORS
    return f"""
    QWidget {{ color: {c["text"]}; font-size: 13px; }}
    QLabel, QPushButton, QLineEdit, QTextEdit, QListWidget, QComboBox {{ font-family: Arial; }}
    QMainWindow, QWidget#desktop-root {{ background: {c["background"]}; }}
    QLabel#eyebrow {{ color: {c["muted"]}; font-size: 10px; font-weight: 700; letter-spacing: 1px; }}
    QLabel#page-title {{ color: {c["text"]}; font-size: 24px; font-weight: 700; }}
    QLabel#page-subtitle, QLabel#muted {{ color: {c["muted"]}; }}
    QLabel#mode-status {{ color: {c["attention"]}; font-weight: 700; }}
    QLabel#core-status {{ color: {c["success"]}; font-size: 14px; font-weight: 700; }}
    QLabel#provider-status {{ color: {c["cyan_bright"]}; }}
    QLabel#status-line {{ color: {c["muted"]}; padding: 3px 0; }}
    QFrame#topbar, QFrame#sidebar, QFrame#observability, QFrame#card {{
        background: {c["surface"]}; border: 1px solid {c["border"]}; border-radius: {RADIUS["md"]}px;
    }}
    QFrame#topbar {{ border-radius: 0; border-left: 0; border-right: 0; border-top: 0; }}
    QFrame#sidebar {{ border-top: 0; border-bottom: 0; border-left: 0; border-radius: 0; }}
    QFrame#observability {{ border-top: 0; border-bottom: 0; border-right: 0; border-radius: 0; }}
    QFrame#card {{ background: {c["surface_raised"]}; }}
    QToolButton#nav-item, QPushButton#nav-item {{ text-align: left; padding: 11px 14px; border: 0; border-radius: {RADIUS["sm"]}px; color: {c["muted"]}; background: transparent; }}
    QToolButton#nav-item:hover, QPushButton#nav-item:hover {{ background: {c["surface_high"]}; color: {c["text"]}; }}
    QToolButton#nav-item:checked, QPushButton#nav-item:checked {{ background: #10344A; color: {c["cyan_bright"]}; border-left: 2px solid {c["cyan"]}; }}
    QPushButton {{ min-height: 34px; padding: 0 14px; border-radius: {RADIUS["sm"]}px; border: 1px solid {c["border_active"]}; background: {c["surface_high"]}; color: {c["text"]}; }}
    QPushButton:hover {{ border-color: {c["cyan"]}; background: #102B3B; }}
    QPushButton:pressed {{ background: #16425A; }}
    QPushButton:disabled {{ color: #536673; border-color: {c["border"]}; }}
    QPushButton#primary-action {{ background: {c["cyan"]}; color: #03111A; border: 0; font-weight: 700; }}
    QPushButton#danger-action {{ color: {c["danger"]}; border-color: #67353D; }}
    QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QListWidget {{ background: {c["surface_high"]}; border: 1px solid {c["border"]}; border-radius: {RADIUS["sm"]}px; padding: 8px; selection-background-color: #155276; }}
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QListWidget:focus {{ border-color: {c["cyan"]}; }}
    QListWidget {{ padding: 4px; }}
    QListWidget::item {{ padding: 10px; border-bottom: 1px solid {c["border"]}; }}
    QListWidget::item:selected {{ background: #10344A; color: {c["text"]}; }}
    QScrollArea {{ border: 0; background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QSplitter::handle {{ background: {c["border"]}; }}
    QProgressBar {{ background: {c["surface_high"]}; border: 0; border-radius: 4px; text-align: center; color: {c["text"]}; }}
    QProgressBar::chunk {{ background: {c["cyan"]}; border-radius: 4px; }}
    """
