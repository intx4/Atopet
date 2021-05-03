#!/bin/bash
if [[ -z $1  ]]; then
  echo "need to give the cell number as first arg"
  exit 1
fi
i=$1
mkdir "./finger_printing/cell_$i"
it=1
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




