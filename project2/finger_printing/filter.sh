#!/bin/bash
filter='tls.app_data && frame.len >= 615'
#ls ./raw | xargs -I @ tshark -r ./raw/@ -w filtered/@ -Y "$filter"
tshark -r raw/network_capture_cell_1.pcap -w filtered/network_capture_cell_1.pcap -Y "$filter"
echo 'done'