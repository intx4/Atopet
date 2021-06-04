#!/bin/bash
size="-100k"
find ./finger_printing/raw -type f -size "$size" | grep -oP 'cell_\d+' | sort | uniq | grep -Po '\d+' > ./finger_printing/failed_runs.txt
if [[ -n $1 ]]; then
  cat ./finger_printing/failed_runs.txt
  exit 0
fi
while read -r line; do
  if [[ $line -eq 40 ]]; then
    continue
  fi
  tmp=$(find "./finger_printing/raw/cell_$line" -type f -size "$size" | grep -Po '\d+\.pcap$' | grep -Po '\d+')
  declare -a failed_instances
  failed_instances=($tmp)
  for index_failed_cmd in "${failed_instances[@]}"; do
    cmd=$(sed -n "$index_failed_cmd"'p' < ./finger_printing/run_commands.txt)
    file_name="./finger_printing/raw/cell_$line/network_capture_round_$index_failed_cmd.pcap"
    tshark -i eth0 -w "$file_name" &
    cmd=${cmd//@/$line}
    sleep 1
    $cmd
    echo "$cmd"
    kill -2 `jobs -p`
    chmod 777 $file_name
  done
done <./finger_printing/failed_runs.txt
