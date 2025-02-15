#!/bin/bash
#script:		xtracdb.sh
#author:		anon
#date:			11.01.2024
#modification:	11.02.2024
#purpose:		extracts tacdb
#usage:			./xtracdb.sh

#exit codes:
#	0	successful exit
#	1	incorrect usage

usage() {
	if [ $# -gt 0 ]; then
		echo "$(tput setaf 1)Usage: $0$(tput sgr 0)"
		exit 1
	fi
}

ask_path() {
	read -ep "Enter path to TACRequester_*.zip: " path
	echo -e "entered path: $path\n"
}

extract_db() {
	unzip $path/TACRequester\*.zip -x *.jar *.pdf -d $PWD
	7z e TACDB.gz
	mv TACDB tacdb.txt
}

main() {
	usage $1
	ask_path
	extract_db
}

main $1

exit 0
