#!/bin/sh
echo "Starting app.py..."
python app.py &
# Start internal service to host the flag
cd /app && python -m http.server 745 &
# Keep the container running
tail -f /dev/null 