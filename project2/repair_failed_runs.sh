#!/bin/bash
size="+800k"
find ./finger_printing/raw -type f -size "$size" | grep -oP 'cell_\d+' | sort | uniq -u | grep -Po '\d+' > ./finger_printing/failed_runs.txt
while read -r line; do
  failed_instance=$(find "./finger_printing/raw/cell_$line" -type f -size "$size" | grep -Po '\d+\.pcap$' | grep -Po '\d+')
  failed_cmd_line=$((failed_instance-7))
  if [[ $failed_cmd_line -le 0 ]]; then
    continue
  fi
    
  cmd=$(sed -n "$failed_cmd_line"'p' < ./finger_printing/run_commands.txt)
  file_name="./finger_printing/raw/cell_$line/network_capture_round_$failed_instance.pcap"
  tshark -i eth0 -w $file_name &
  cmd=${cmd//@/$line}
  sleep 1
  $cmd
  echo "$cmd"
  kill -2 `jobs -p`
  chmod 777 $file_name
done <./finger_printing/failed_runs.txt
