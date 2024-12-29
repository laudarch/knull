#!/usr/bin/env bash
#
#
# count the total number of IPs in a file containing multiple CIDRs
# Usage:
# ./$0 input_file 
#
#
# Check if correct number of arguments is provided
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 input_file"
  exit 1
fi

# Assign input and output file arguments
input_file=$1

# Check if input file exists
if [[ ! -f $input_file ]]; then
  echo "Error: Input file '$input_file' does not exist."
  exit 2
fi

total=`sudo nmap -n -sL -iL $input_file | wc -l`

echo "Total IP addresses is '$total'"