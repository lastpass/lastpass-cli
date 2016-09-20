add_custom_target(predoc a2x --no-xmllint -f manpage ${CMAKE_SOURCE_DIR}/doc/lpass.1.txt)
add_custom_target(doc asciidoc -b html5 -a data-uri -a icons -a toc2 -o lpass.1.html ${CMAKE_SOURCE_DIR}/doc/lpass.1.txt DEPENDS predoc)
