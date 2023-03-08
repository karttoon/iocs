#!/usr/bin/python
import sys, oletools.olevba, re

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "karttoon@gmail.com"
__version__ = "1.0.0"
__date__    = "08MAR2023"

# Variant - a99eb971a4d11235924443dfd0308e731205b6320e6939526d94f91a43c64248

vbaparser = oletools.olevba.VBA_Parser(sys.argv[1]).extract_macros()

if vbaparser:
    for (filename, stream_path, vba_filename, vba_code) in vbaparser:
        if "AutoOpen" in vba_code:

            indexValue = dict()
            indexAlphabet = dict()
            indexArray = dict()

            for line in vba_code.splitlines():

                # Variable Values | fOueQX = 26
                if re.search("^[a-zA-Z]+ = [0-9]+", line):
                    variable = line.split(" ")[0]
                    index = int(line.split(" ")[2])
                    indexValue[variable] = index

                # Replace | hzQtU = fOueQX
                if re.search("^[a-zA-Z]+ = [a-zA-Z]+$", line):
                    newVar = line.split(" ")[0]
                    oldVar = line.split(" ")[2]
                    try:
                        indexValue[newVar] = indexValue[oldVar]
                    except:
                        pass

                # Alphabets | blSoELVq = "fxNNbmIerSxhpodpsFcqTYulnMJVsgMDboqDrDOyc [...]
                if re.search("^[a-zA-Z]+ = \".+?\"", line):
                    variable = line.split(" ")[0]
                    alpha = line.split(" ")[2].strip("\"")
                    indexAlphabet[variable] = alpha

                # Indexed Arrays | sHjDF(0) = yYiP
                if re.search("^[a-zA-Z]+\([0-9]+\) = [a-zA-Z]+", line):
                    variable = line.split(" ")[0].split("(")[0]
                    index = int(line.split("(")[1].split(")")[0])
                    value = indexValue[line.split(" ")[2]]

                    if variable not in indexArray:
                        indexArray[variable] = list()
                        indexArray[variable].insert(index, value)
                    else:
                        indexArray[variable].insert(index, value)

                # Print Func | hrOyFMRd = Motztvi(blSoELVq, sHjDF, hzQtU)
                if re.search("^[a-zA-Z]+ = [a-zA-Z]+\([a-zA-Z]+, [a-zA-Z]+, [a-zA-Z]+\)", line):
                    alpha = line.split("(")[1].split(",")[0].strip()
                    array = line.split("(")[1].split(",")[1].strip()
                    count = indexValue[line.split("(")[1].split(",")[2].strip(") ")]

                    decString = str()

                    try:
                        for entry in indexArray[array]:
                            decString += indexAlphabet[alpha][(entry-1) % len(indexAlphabet[alpha])]

                        print(decString[0:count])
                    except:
                        pass


