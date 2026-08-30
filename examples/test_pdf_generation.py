from mlda_swarm.reporting.pdf_report import (
    compile_latex_to_pdf,
)


pdf_path = compile_latex_to_pdf(
    tex_path="output/generated_report.tex",
    output_dir="output",
    run_id="run-001",
)

print(f"PDF generated: {pdf_path}")