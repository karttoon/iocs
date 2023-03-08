#!/bin/bash

#__author__  = "Jeff White [karttoon] @noottrak"
#__email__   = "karttoon@gmail.com"
#__version__ = "1.0.0"
#__date__    = "07MAR2023"

# Variant - 2e116e6a43dcc2ee55df34664a7d5bfae36918f3a8ce5af97be6cb99e3a4de5b

grep -E "^[a-zA-Z]+ = [0-9]+" $1 | while read entry; do
	len=$(echo $entry |awk '{print $3}')
	encString=$(grep "$entry" $1 -A1 |tail -n1 |awk '{print $3}' |sed -e's/"//g')
	decString=""
	for index in $(grep "$entry" $1 -A$(($len+1)) |tail -n$len |awk '{print $3}'); do
		decString+=$(echo $encString |cut -c $index)
	done
	echo $decString
done

