#!/bin/bash
filter='tls.app_data && frame.len >= 615'
ls -r raw | egrep ^cell_ > tmp.txt
while read -r line; do
  dir_name_new="./filtered/$line/"
  mkdir "$dir_name_new" 2> /dev/null
  dir_name_old="./raw/$line/"
  ls "$dir_name_old" | xargs -I @ tshark -r "$dir_name_old"@ -Y "$filter" -w "$dir_name_new"@ -F libpcap
done <./tmp.txt
rm tmp.txt