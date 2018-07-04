# CopyIfNotExists, written by Hugo Leisink <hugo@leisink.net>
#
install(CODE "
	macro(copy_if_not_exists SRC DEST)
		get_filename_component(filename \${SRC} NAME)
		if(NOT EXISTS \"\$ENV{DESTDIR}/\${DEST}/\${filename}\")
			file(INSTALL \"\${SRC}\" DESTINATION \"\${DEST}\")
		else()
			message(\"-- Skipping  : \$ENV{DESTDIR}/\${DEST}/\${filename}\")
		endif()
	endmacro()
")
