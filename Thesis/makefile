PICDIR = ./images

bibfiles = $(wildcard *.bib)

depsvg = $(wildcard $(PICDIR)/*.svg)
svgpdf = $(patsubst %.svg,%.pdf,$(depsvg))

all: thesis.pdf

thesis.pdf: thesis.tex $(bibfiles) $(svgpdf)
	mkdir -p out
	pdflatex -file-line-error -output-directory=out thesis.tex
	biber out/thesis.bcf || true
	pdflatex -output-directory=out thesis.tex
	cp out/thesis.pdf thesis.pdf

$(PICDIR)/%.pdf: $(PICDIR)/%.svg 
	inkscape --export-type=pdf --export-latex $@ $<

clean:
	rm -rf out || true
	rm $(PICDIR)/*.pdf || true
	rm thesis.pdf || true

