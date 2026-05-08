"""
Cyber Global Shield — Export CSV/PDF
Export des rapports, logs, alertes et analyses au format CSV et PDF.
"""

import csv
import io
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    PageBreak, Image, ListFlowable, ListItem,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)


class ExportService:
    """Service for exporting data to CSV and PDF formats."""

    @staticmethod
    def to_csv(
        data: List[Dict[str, Any]],
        filename: str = "export.csv",
        columns: Optional[List[str]] = None,
    ) -> StreamingResponse:
        """Export data as CSV file."""
        if not data:
            data = [{"message": "No data available"}]

        if columns is None:
            columns = list(data[0].keys())

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()

        for row in data:
            # Flatten nested dicts
            flat_row = {}
            for col in columns:
                value = row.get(col, "")
                if isinstance(value, (dict, list)):
                    import json
                    value = json.dumps(value)
                flat_row[col] = str(value)
            writer.writerow(flat_row)

        output.seek(0)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "text/csv; charset=utf-8",
            },
        )

    @staticmethod
    def to_pdf(
        data: List[Dict[str, Any]],
        title: str = "Cyber Global Shield Report",
        filename: str = "report.pdf",
        columns: Optional[List[str]] = None,
        orientation: str = "portrait",
    ) -> StreamingResponse:
        """Export data as PDF file."""
        if not data:
            data = [{"message": "No data available"}]

        if columns is None:
            columns = list(data[0].keys())

        # Set page size
        if orientation == "landscape":
            page_size = landscape(A4)
        else:
            page_size = A4

        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=page_size,
            title=title,
            author="Cyber Global Shield",
            subject="Security Report",
        )

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor("#1a237e"),
        )
        subtitle_style = ParagraphStyle(
            "CustomSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#666666"),
            spaceAfter=20,
        )
        header_style = ParagraphStyle(
            "HeaderStyle",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.white,
            alignment=TA_CENTER,
        )
        cell_style = ParagraphStyle(
            "CellStyle",
            parent=styles["Normal"],
            fontSize=7,
            alignment=TA_LEFT,
        )

        # Build content
        elements = []

        # Title
        elements.append(Paragraph(title, title_style))
        elements.append(
            Paragraph(
                f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                subtitle_style,
            )
        )
        elements.append(
            Paragraph(f"Records: {len(data)}", subtitle_style)
        )
        elements.append(Spacer(1, 20))

        # Table header
        table_data = []
        header_row = [Paragraph(col.replace("_", " ").title(), header_style) for col in columns]
        table_data.append(header_row)

        # Table data
        for row in data:
            row_data = []
            for col in columns:
                value = row.get(col, "")
                if isinstance(value, (dict, list)):
                    import json
                    value = json.dumps(value)[:100]
                row_data.append(Paragraph(str(value)[:80], cell_style))
            table_data.append(row_data)

        # Calculate column widths
        available_width = page_size[0] - 2 * inch
        col_width = available_width / len(columns)
        col_widths = [col_width] * len(columns)

        # Create table
        table = Table(table_data, colWidths=col_widths, repeatRows=1)

        # Table style
        table_style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f5f5f5")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ])
        table.setStyle(table_style)

        elements.append(table)

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf",
            },
        )

    @staticmethod
    def export_logs_csv(logs: List[Dict]) -> StreamingResponse:
        """Export logs specifically as CSV."""
        columns = [
            "timestamp", "org_id", "src_ip", "dst_ip", "event_type",
            "severity", "protocol", "port", "action", "message",
        ]
        return ExportService.to_csv(logs, "logs_export.csv", columns)

    @staticmethod
    def export_alerts_csv(alerts: List[Dict]) -> StreamingResponse:
        """Export alerts specifically as CSV."""
        columns = [
            "id", "created_at", "org_id", "type", "severity",
            "source", "status", "assigned_to", "description",
        ]
        return ExportService.to_csv(alerts, "alerts_export.csv", columns)

    @staticmethod
    def export_anomalies_csv(anomalies: List[Dict]) -> StreamingResponse:
        """Export anomalies specifically as CSV."""
        columns = [
            "timestamp", "org_id", "score", "threshold",
            "feature_values", "prediction", "model_version",
        ]
        return ExportService.to_csv(anomalies, "anomalies_export.csv", columns)

    @staticmethod
    def generate_report_pdf(
        title: str,
        sections: List[Dict[str, Any]],
    ) -> StreamingResponse:
        """Generate a comprehensive PDF report with multiple sections."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            title=title,
            author="Cyber Global Shield",
        )

        styles = getSampleStyleSheet()
        elements = []

        # Title page
        elements.append(Spacer(1, 100))
        elements.append(Paragraph(title, ParagraphStyle(
            "ReportTitle", parent=styles["Title"], fontSize=32,
            textColor=colors.HexColor("#1a237e"), alignment=TA_CENTER,
        )))
        elements.append(Spacer(1, 30))
        elements.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            ParagraphStyle("Date", parent=styles["Normal"], alignment=TA_CENTER),
        ))
        elements.append(PageBreak())

        # Sections
        for section in sections:
            elements.append(Paragraph(
                section.get("title", "Section"),
                ParagraphStyle(
                    "SectionTitle", parent=styles["Heading1"],
                    fontSize=18, textColor=colors.HexColor("#1a237e"),
                    spaceAfter=15, spaceBefore=20,
                ),
            ))

            if "text" in section:
                elements.append(Paragraph(section["text"], styles["Normal"]))
                elements.append(Spacer(1, 10))

            if "data" in section and section["data"]:
                columns = section.get("columns", list(section["data"][0].keys()))
                table_data = [[Paragraph(col.title(), styles["Normal"]) for col in columns]]
                for row in section["data"]:
                    table_data.append([
                        Paragraph(str(row.get(col, ""))[:60], styles["Normal"])
                        for col in columns
                    ])

                table = Table(table_data, repeatRows=1)
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]))
                elements.append(table)

            elements.append(Spacer(1, 15))

        doc.build(elements)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{title.lower().replace(" ", "_")}.pdf"',
            },
        )


# Singleton
export_service = ExportService()
