all: clean draft/index.html

clean:
	rm -rf draft/index.html

draft/index.html: specification.dev.markdown template.erb
	kramdown --parse-block-html --template='template.erb' specification.dev.markdown > draft/index.html

publish: all
	git commit -am Regenerate.
	git push github master
	git push github master:gh-pages
