all: clean draft/index.html

clean:
	rm -rf draft/index.html

draft/index.html: specification.dev.markdown template.erb
	kramdown --parse-block-html --template='template.erb' specification.dev.markdown > draft/index.html
