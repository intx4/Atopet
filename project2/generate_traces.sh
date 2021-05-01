#!/bin/bash
i=0

while [[ i=$((i+1)) -lt 101 ]]; do
  file_name="./finger_printing/network_capture_cell_$i.pcap"
  tshark -i eth0 -w $file_name &
  while read -r line; do
    cmd=${line//@/$i}
    $cmd
    echo "$cmd"
  done <./finger_printing/run_commands.txt
  echo 'done'
  kill -2 `jobs -p`
  chmod 777 $file_name
done
