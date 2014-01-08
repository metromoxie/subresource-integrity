all: clean index.html

clean:
	rm -rf index.html

index.html: specification.dev.markdown template.erb
	kramdown --parse-block-html --template='template.erb' specification.dev.markdown > index.html

publish: all
	git commit -am Regenerate.
	git push github master
	git push github master:gh-pages
