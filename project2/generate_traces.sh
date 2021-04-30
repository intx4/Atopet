#!/bin/bash
i=3

while [[ i=$((i+1)) -lt 5 ]]; do
  file_name="./finger_printing/network_capture_cell_$i.pcap"
  tshark -w $file_name &
  while read -r line; do
    cmd=${line//@/$i}
    $cmd &> /dev/null
  done <./finger_printing/run_commands.txt
  echo 'done'
  kill -2 %"$1"
  chmod 777 $file_name
done
