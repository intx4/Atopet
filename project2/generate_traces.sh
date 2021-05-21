#!/bin/bash
i=0
while [[ i=$((i+1)) -lt 101 ]]; do
  # Change this to change the ouptut file index
  it=30
  while read -r line; do
    file_name="./finger_printing/raw/cell_$i/network_capture_round_$it.pcap"
    tshark -i eth0 -w $file_name &
    cmd=${line//@/$i}
    sleep 1
    $cmd
    echo "$cmd"
    kill -2 `jobs -p`
    chmod 777 $file_name
    it=$((it+1))
  done <./finger_printing/run_commands.txt
  echo "next $((i+1))"
  break
done
