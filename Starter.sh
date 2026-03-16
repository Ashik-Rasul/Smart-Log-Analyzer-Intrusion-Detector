#!/bin/bash

echo "[+] Starting Monitoring Tools..."

# Run Python programs in background
python3 brute_force_detection.py &
PID1=$!

python3 sn.py &
PID2=$!

# Run shell scripts in background
bash unusual_login_alert.sh &
PID3=$!

bash Mailer_blacklist_fromSnort.sh &
PID4=$!

echo "-----------------------------------------"
echo "All monitoring tools started             "
echo "PIDs                              :      "
echo "Brute Force Detector              : $PID1"
echo "Sniffer                           : $PID2"
echo "unusual_login_alert.sh            : $PID3"
echo "mailer_blacklist_fromSnort        : $PID4"
echo "-----------------------------------------"

# Optional: save PIDs
echo $PID1 $PID2 $PID3 $PID4 > monitor_pids.txt

echo "Processes running in background"
