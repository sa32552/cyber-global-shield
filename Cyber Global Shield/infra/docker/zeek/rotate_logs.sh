#!/bin/bash
# Cyber Global Shield - Zeek Log Rotation & Shipment
# Compresses, archives, and ships logs to Vector/Kafka pipeline

set -euo pipefail

LOG_DIR="/usr/local/zeek/logs"
ARCHIVE_DIR="/usr/local/zeek/logs/archive"
S3_BUCKET="${S3_BUCKET:-cyber-global-shield-logs}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

mkdir -p "$ARCHIVE_DIR"

# Get the rotated log file
ROTATED_FILE="$1"
BASENAME=$(basename "$ROTATED_FILE")
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
ARCHIVE_NAME="${BASENAME%.*}_${TIMESTAMP}.log.gz"
ARCHIVE_PATH="$ARCHIVE_DIR/$ARCHIVE_NAME"

# Compress
gzip -c "$ROTATED_FILE" > "$ARCHIVE_PATH"

# Ship to S3 (if configured)
if command -v aws &> /dev/null && [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
    aws s3 cp "$ARCHIVE_PATH" "s3://$S3_BUCKET/zeek/$(date -u +%Y/%m/%d)/$ARCHIVE_NAME" \
        --storage-class STANDARD_IA \
        --sse AES256
fi

# Cleanup old archives
find "$ARCHIVE_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Signal Vector that new data is available
if [ -S /var/run/vector.sock ]; then
    echo "{\"file\":\"$ARCHIVE_PATH\",\"source\":\"zeek\",\"timestamp\":\"$(date -u -Iseconds)\"}" | \
        nc -U /var/run/vector.sock
fi

echo "Rotated: $ROTATED_FILE -> $ARCHIVE_PATH"
