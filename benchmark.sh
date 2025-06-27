#!/bin/bash

SSSLP="./SSSLP -i example.com"

for FILE in `ls *.log` ; do
    $SSSLP --version
    LINES="`wc -l $FILE | cut -d' ' -f1`"
    RELEVANTLINES="`grep severity $FILE | wc -l`"
    echo "File <$FILE> with <$RELEVANTLINES> relevant out of <$LINES> total lines:"
    echo "CSV mode:"
    for COUNT in {1..5} ; do
        echo "Run $COUNT:"
        time $SSSLP $FILE | grep -E '^(real|user|sys)'
        echo
    done
    echo "JSON mode:"
    for COUNT in {1..5} ; do
        echo "Run $COUNT:"
        time $SSSLP -J $FILE | grep -E '^(real|user|sys)'
        echo
    done
    echo
    echo
done
