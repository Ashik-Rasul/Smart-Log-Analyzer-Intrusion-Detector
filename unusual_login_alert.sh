#!/bin/bash

LOG_FILE="/var/log/auth.log"
ADMIN_EMAIL="admin@gmail.com"

START_TIME=0
END_TIME=7

tail -Fn0 "$LOG_FILE" | while read line
do
    if echo "$line" | grep "Accepted"; then
        
        HOUR=$(date +"%H")

        if [ "$HOUR" -ge "$START_TIME" ] && [ "$HOUR" -lt "$END_TIME" ]; then
            
            USER=$(echo "$line" | awk '{print $9}')
            IP=$(echo "$line" | awk '{print $11}')

            MESSAGE="Unusual SSH login detected!

User: $USER
IP Address: $IP
Time: $(date)

Log Entry:
$line"

            echo "$MESSAGE" | mail -s "ALERT: Unusual SSH Login" "$ADMIN_EMAIL"

        fi
    fi
done
