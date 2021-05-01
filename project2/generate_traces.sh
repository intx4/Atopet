#!/bin/bash
i=0

while [[ i=$((i+1)) -lt 101 ]]; do
  it=1
  mkdir "./finger_printing/cell_$i"
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
done
