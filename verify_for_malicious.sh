#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Invalid number of arguments in shell script."
    exit 1
fi

input_file_path=$1

# Make the file readable
chmod +r "$input_file_path"

printFileName() 
{
    echo $(basename "$input_file_path")   
    # Return file to previous state 
    chmod 000 "$input_file_path"
    exit 0
}

# Check the file number of lines
line_count=$(wc -l < "$input_file_path")

if [ "$line_count" -lt 3 ]; then 
    echo "Fewer than 3 lines:"
    printFileName
fi

# Check file number of words 
word_count=$(wc -w < "$input_file_path")

if [ "$word_count" -gt 1000 ]; then 
    echo "More than 1000 words:"
    printFileName
fi

# Check the file number of characters
no_characters=$(wc -m < "$input_file_path")

if [ "$no_characters" -gt 2000 ]; then 
    echo "More than 2000 characters:"
    printFileName
fi

# Use search for non-ASCII characters
if grep -q "[^[:print:]]" "$input_file_path"; then
    echo "Contains non-printable characters:"
    printFileName
fi

KEYWORDS=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")

# Loop through each keyword
for keyword in "${KEYWORDS[@]}"; do
    # Search for keyword in file
    if grep -qs "$keyword" "$input_file_path"; then
        echo "Contains keyword '$keyword':"
        printFileName
    fi
done

echo "SAFE"

# Return file to previous state 
chmod 000 "$input_file_path"