#!/usr/bin/env bash
#
#
# Extract CIDR from file into output_file
#
# Usage:
# ./$0 input_file output_file
#
#

# Check if correct number of arguments is provided
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 input_file output_file"
  exit 1
fi

# Assign input and output file arguments
input_file=$1
output_file=$2

# Check if input file exists
if [[ ! -f $input_file ]]; then
  echo "Error: Input file '$input_file' does not exist."
  exit 2
fi

# Extract CIDR blocks and save to output file
awk '{for(i=1;i<=NF;i++) if($i ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/) print $i}' "$input_file" | sed 's/"//g' | sed 's/,//g' > "$output_file"

echo "CIDR blocks have been extracted to '$output_file'."

