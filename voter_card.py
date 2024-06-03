#!/usr/bin/env python3

from fpdf import FPDF, YPos, XPos

def create_pdf(url, pseudonym):
    pdf = FPDF(format=(200,80))
    pdf.add_page()
    pdf.set_font("helvetica", size=18)
    pdf.cell(h=10, text=f"Sinu hääletustunnus on:", new_y=YPos.NEXT, new_x=XPos.LEFT)
    pdf.cell(w=20, h=10, text=f"> {pseudonym}", link=f"{url}/{pseudonym}", ln=1)
    pdf.cell(h=10, text="Hääletuskeskkond asub aadressil:", ln=1)
    pdf.cell(w=20, h=10, text=f"> {url}", link=f"{url}/{pseudonym}", ln=1)
    pdf.cell(h=10, text="Aitäh, et võtad digidemokraatiat tõsiselt!", ln=1)

    return pdf.output()