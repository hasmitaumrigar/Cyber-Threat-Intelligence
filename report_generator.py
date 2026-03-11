# report_generator.py

from fpdf import FPDF

def generate_report(data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Threat Intelligence Report", ln=True, align="C")
    pdf.ln(10)
    for key, value in data.items():
        pdf.cell(0, 10, f"{key}: {value}", ln=True)
    pdf.output("Threat_Report.pdf")