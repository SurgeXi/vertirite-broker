# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Maestro AI — Document Engine

Read and create Microsoft Office docs, PDFs, spreadsheets, presentations.
Access email clients for queries.

Capabilities:
- Read: PDF, DOCX, XLSX, PPTX, CSV, TXT, JSON, Markdown
- Create: PDF, DOCX, XLSX, CSV, TXT, Markdown
- Email: read from IMAP, send via SMTP
- Convert between formats
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("maestro.documents")


# ── PDF Operations ────────────────────────────────────────────────────

async def read_pdf(file_path: str) -> dict:
    """Read a PDF file and extract text content."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return {"status": "error", "content": f"File not found: {path}"}

    # Try pdftotext (poppler) first, then Python fallback
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return {
                "status": "ok",
                "content": result.stdout[:50000],
                "pages": result.stdout.count("\f") + 1,
                "path": str(path),
            }
    except FileNotFoundError:
        pass

    # Python fallback with PyPDF2 or similar
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(str(path))
        text = ""
        for page in doc:
            text += page.get_text() + "\n---\n"
        doc.close()
        return {"status": "ok", "content": text[:50000], "pages": len(doc), "path": str(path)}
    except ImportError:
        pass

    return {"status": "error", "content": "No PDF reader available. Install poppler-utils or PyMuPDF."}


async def create_pdf(content: str, output_path: str, title: str = "Document") -> dict:
    """Create a PDF from text content."""
    path = Path(output_path).expanduser().resolve()
    try:
        # Use reportlab if available
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas as pdf_canvas
        from reportlab.lib.units import inch

        c = pdf_canvas.Canvas(str(path), pagesize=letter)
        c.setTitle(title)
        c.setFont("Helvetica", 12)

        y = 750
        for line in content.split("\n"):
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 12)
                y = 750
            c.drawString(72, y, line[:100])
            y -= 14
        c.save()
        return {"status": "ok", "path": str(path), "title": title}
    except ImportError:
        pass

    # Fallback: use macOS textutil or write HTML then convert
    try:
        html = f"<html><head><title>{title}</title></head><body><pre>{content}</pre></body></html>"
        html_path = str(path).replace(".pdf", ".html")
        Path(html_path).write_text(html)
        result = subprocess.run(
            ["cupsfilter", html_path],
            capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            path.write_bytes(result.stdout)
            os.unlink(html_path)
            return {"status": "ok", "path": str(path), "title": title}
    except Exception:
        pass

    # Last resort: write as text file
    path.write_text(content)
    return {"status": "ok", "path": str(path), "note": "Saved as text (no PDF engine available)"}


# ── Microsoft Office Operations ───────────────────────────────────────

async def read_docx(file_path: str) -> dict:
    """Read a Word document."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return {"status": "error", "content": f"File not found: {path}"}
    try:
        import docx
        doc = docx.Document(str(path))
        paragraphs = [p.text for p in doc.paragraphs]
        tables = []
        for table in doc.tables:
            rows = []
            for row in table.rows:
                rows.append([cell.text for cell in row.cells])
            tables.append(rows)
        return {
            "status": "ok",
            "content": "\n".join(paragraphs),
            "paragraphs": len(paragraphs),
            "tables": len(tables),
            "table_data": tables[:5],
            "path": str(path),
        }
    except ImportError:
        # Fallback: use textutil on macOS
        try:
            result = subprocess.run(
                ["textutil", "-convert", "txt", "-stdout", str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return {"status": "ok", "content": result.stdout[:50000], "path": str(path)}
        except Exception:
            pass
    return {"status": "error", "content": "Install python-docx to read Word documents."}


async def create_docx(content: str, output_path: str, title: str = "Document") -> dict:
    """Create a Word document."""
    path = Path(output_path).expanduser().resolve()
    try:
        import docx
        doc = docx.Document()
        doc.add_heading(title, 0)
        for para in content.split("\n\n"):
            doc.add_paragraph(para)
        doc.save(str(path))
        return {"status": "ok", "path": str(path), "title": title}
    except ImportError:
        path.write_text(content)
        return {"status": "ok", "path": str(path), "note": "Saved as text (python-docx not available)"}


async def read_xlsx(file_path: str) -> dict:
    """Read an Excel spreadsheet."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return {"status": "error", "content": f"File not found: {path}"}
    try:
        import openpyxl
        wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
        sheets = {}
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            rows = []
            for row in ws.iter_rows(max_row=100, values_only=True):
                rows.append([str(cell) if cell is not None else "" for cell in row])
            sheets[sheet_name] = {"rows": len(rows), "columns": len(rows[0]) if rows else 0, "data": rows[:50]}
        wb.close()
        return {"status": "ok", "sheets": sheets, "sheet_count": len(sheets), "path": str(path)}
    except ImportError:
        return {"status": "error", "content": "Install openpyxl to read Excel files."}


async def create_xlsx(data: list[list], output_path: str, sheet_name: str = "Sheet1", title: str = "Spreadsheet") -> dict:
    """Create an Excel spreadsheet from a list of rows."""
    path = Path(output_path).expanduser().resolve()
    try:
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = sheet_name
        for row in data:
            ws.append(row)
        wb.save(str(path))
        return {"status": "ok", "path": str(path), "rows": len(data), "title": title}
    except ImportError:
        # Fallback to CSV
        csv_path = str(path).replace(".xlsx", ".csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(data)
        return {"status": "ok", "path": csv_path, "note": "Saved as CSV (openpyxl not available)"}


async def read_pptx(file_path: str) -> dict:
    """Read a PowerPoint presentation."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return {"status": "error", "content": f"File not found: {path}"}
    try:
        from pptx import Presentation
        prs = Presentation(str(path))
        slides = []
        for slide in prs.slides:
            texts = []
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    texts.append(shape.text)
            slides.append({"slide_number": len(slides) + 1, "content": "\n".join(texts)})
        return {"status": "ok", "slides": slides, "slide_count": len(slides), "path": str(path)}
    except ImportError:
        return {"status": "error", "content": "Install python-pptx to read PowerPoint files."}


# ── Email Operations ──────────────────────────────────────────────────

async def read_emails(
    server: str,
    email: str,
    password: str,
    folder: str = "INBOX",
    limit: int = 10,
    search: str = "ALL",
) -> dict:
    """Read emails from an IMAP server."""
    try:
        import imaplib
        import email as email_lib
        from email.header import decode_header

        mail = imaplib.IMAP4_SSL(server)
        mail.login(email, password)
        mail.select(folder)

        _, message_ids = mail.search(None, search)
        ids = message_ids[0].split()[-limit:]

        emails = []
        for msg_id in reversed(ids):
            _, msg_data = mail.fetch(msg_id, "(RFC822)")
            raw = email_lib.message_from_bytes(msg_data[0][1])

            subject = decode_header(raw["Subject"])[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode("utf-8", errors="replace")

            from_addr = raw["From"]
            date = raw["Date"]

            body = ""
            if raw.is_multipart():
                for part in raw.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                        break
            else:
                body = raw.get_payload(decode=True).decode("utf-8", errors="replace")

            emails.append({
                "subject": str(subject),
                "from": str(from_addr),
                "date": str(date),
                "body": body[:2000],
            })

        mail.logout()
        return {"status": "ok", "emails": emails, "count": len(emails), "folder": folder}
    except Exception as e:
        return {"status": "error", "content": f"Email access failed: {e}"}


async def send_email(
    smtp_server: str,
    smtp_port: int,
    email_from: str,
    password: str,
    email_to: str,
    subject: str,
    body: str,
) -> dict:
    """Send an email via SMTP."""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart()
        msg["From"] = email_from
        msg["To"] = email_to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_from, password)
            server.send_message(msg)

        return {"status": "ok", "to": email_to, "subject": subject}
    except Exception as e:
        return {"status": "error", "content": f"Send failed: {e}"}


# ── Universal File Reader ─────────────────────────────────────────────

async def read_document(file_path: str) -> dict:
    """Smart document reader — detects type and reads accordingly."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return {"status": "error", "content": f"File not found: {path}"}

    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return await read_pdf(str(path))
    elif suffix == ".docx":
        return await read_docx(str(path))
    elif suffix in (".xlsx", ".xls"):
        return await read_xlsx(str(path))
    elif suffix == ".pptx":
        return await read_pptx(str(path))
    elif suffix == ".csv":
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            rows = list(reader)[:100]
        return {"status": "ok", "content": "\n".join(",".join(r) for r in rows), "rows": len(rows), "path": str(path)}
    elif suffix == ".json":
        data = json.loads(path.read_text())
        return {"status": "ok", "content": json.dumps(data, indent=2)[:50000], "path": str(path)}
    elif suffix in (".txt", ".md", ".log", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".sh", ".py", ".js", ".ts", ".html", ".css"):
        content = path.read_text(encoding="utf-8", errors="replace")
        return {"status": "ok", "content": content[:50000], "lines": content.count("\n"), "path": str(path)}
    else:
        # Try reading as text
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            return {"status": "ok", "content": content[:50000], "path": str(path)}
        except Exception:
            return {"status": "error", "content": f"Cannot read file type: {suffix}"}


# ── Format Summary ────────────────────────────────────────────────────

def get_supported_formats() -> dict:
    """Return which formats are supported and what libs are available."""
    formats = {
        "read": {
            "pdf": False,
            "docx": False,
            "xlsx": False,
            "pptx": False,
            "csv": True,
            "json": True,
            "txt": True,
            "md": True,
        },
        "create": {
            "pdf": False,
            "docx": False,
            "xlsx": False,
            "csv": True,
            "txt": True,
            "md": True,
        },
        "email": {
            "imap_read": True,
            "smtp_send": True,
        },
    }

    # Check available libraries
    try:
        subprocess.run(["pdftotext", "-v"], capture_output=True, timeout=5)
        formats["read"]["pdf"] = True
    except Exception:
        pass

    try:
        import fitz
        formats["read"]["pdf"] = True
    except ImportError:
        pass

    for mod, key in [("docx", "docx"), ("openpyxl", "xlsx"), ("pptx", "pptx")]:
        try:
            __import__(mod)
            formats["read"][key] = True
            if key != "pptx":
                formats["create"][key] = True
        except ImportError:
            pass

    try:
        from reportlab.pdfgen import canvas
        formats["create"]["pdf"] = True
    except ImportError:
        pass

    return formats
