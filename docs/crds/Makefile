CRD_REF_DOCS_VER := v0.3.0
CRD_REF_DOCS := go run github.com/elastic/crd-ref-docs@$(CRD_REF_DOCS_VER)

.PHONY: all
all: asciidoc

.PHONY: asciidoc
asciidoc:
	$(CRD_REF_DOCS) --log-level INFO --config=config.yml --renderer=asciidoctor --templates-dir=templates/asciidoctor --source-path=../../api --output-path=CRD-docs-for-docs-repo.adoc
