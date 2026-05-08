#!/usr/bin/env python3
"""
Cyber Global Shield — ClickHouse Backup & Restore Script
Backup automatisé avec retention policy, compression, et upload S3.
"""

import os
import sys
import json
import gzip
import shutil
import hashlib
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Tuple

import structlog

logger = structlog.get_logger(__name__)

# =============================================================================
# Configuration
# =============================================================================

BACKUP_DIR = os.getenv("CLICKHOUSE_BACKUP_DIR", "/var/backups/clickhouse")
S3_BUCKET = os.getenv("CLICKHOUSE_BACKUP_S3_BUCKET", "")
S3_ENDPOINT = os.getenv("CLICKHOUSE_BACKUP_S3_ENDPOINT", "")
S3_ACCESS_KEY = os.getenv("CLICKHOUSE_BACKUP_S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.getenv("CLICKHOUSE_BACKUP_S3_SECRET_KEY", "")
RETENTION_DAYS = int(os.getenv("CLICKHOUSE_BACKUP_RETENTION_DAYS", "30"))
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = os.getenv("CLICKHOUSE_PORT", "8123")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "cyber_shield")

# Tables to backup (in order of dependency)
TABLES = [
    "logs",
    "alerts",
    "anomalies",
    "soar_executions",
    "fl_rounds",
    "threat_intel",
    "audit_log",
]

# =============================================================================
# Backup Manager
# =============================================================================

class ClickHouseBackup:
    """Manages ClickHouse backup and restore operations."""

    def __init__(self):
        self.backup_dir = Path(BACKUP_DIR)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.backup_name = f"cgs_backup_{self.timestamp}"
        self.backup_path = self.backup_dir / self.backup_name

    def _clickhouse_query(self, query: str) -> str:
        """Execute a ClickHouse query and return results."""
        cmd = [
            "clickhouse-client",
            "--host", CLICKHOUSE_HOST,
            "--port", CLICKHOUSE_PORT,
            "--user", CLICKHOUSE_USER,
            "--password", CLICKHOUSE_PASSWORD,
            "--query", query,
            "--format", "JSONEachRow",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error("clickhouse_query_failed", query=query[:100], error=e.stderr)
            raise

    def create_backup(self, tables: Optional[List[str]] = None) -> Dict:
        """
        Create a full backup of specified tables.
        Returns backup metadata.
        """
        tables = tables or TABLES
        backup_info = {
            "backup_name": self.backup_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": CLICKHOUSE_DATABASE,
            "tables": {},
            "total_size_bytes": 0,
            "status": "in_progress",
        }

        # Create backup directory
        self.backup_path.mkdir(parents=True, exist_ok=True)

        logger.info("backup_started", backup_name=self.backup_name, tables=tables)

        for table in tables:
            try:
                table_info = self._backup_table(table)
                backup_info["tables"][table] = table_info
                backup_info["total_size_bytes"] += table_info["size_bytes"]
                logger.info("table_backed_up", table=table, rows=table_info["rows"])
            except Exception as e:
                logger.error("table_backup_failed", table=table, error=str(e))
                backup_info["tables"][table] = {"status": "failed", "error": str(e)}

        # Create metadata file
        metadata_path = self.backup_path / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(backup_info, f, indent=2)

        # Create checksum
        self._create_checksum()

        # Compress backup
        archive_path = self._compress_backup()

        # Upload to S3 if configured
        if S3_BUCKET:
            self._upload_to_s3(archive_path)

        backup_info["status"] = "completed"
        backup_info["archive_path"] = str(archive_path)
        backup_info["archive_size_bytes"] = archive_path.stat().st_size

        logger.info(
            "backup_completed",
            backup_name=self.backup_name,
            total_size=backup_info["total_size_bytes"],
            archive_size=backup_info["archive_size_bytes"],
        )

        return backup_info

    def _backup_table(self, table_name: str) -> Dict:
        """Backup a single table to a TSV file."""
        output_path = self.backup_path / f"{table_name}.tsv.gz"

        # Get row count first
        count_query = f"SELECT count() FROM {CLICKHOUSE_DATABASE}.{table_name}"
        row_count = int(self._clickhouse_query(count_query).strip())

        if row_count == 0:
            return {"status": "empty", "rows": 0, "size_bytes": 0}

        # Export table to compressed TSV
        export_query = (
            f"SELECT * FROM {CLICKHOUSE_DATABASE}.{table_name} "
            f"ORDER BY timestamp DESC "
            f"FORMAT TSV"
        )

        cmd = [
            "clickhouse-client",
            "--host", CLICKHOUSE_HOST,
            "--port", CLICKHOUSE_PORT,
            "--user", CLICKHOUSE_USER,
            "--password", CLICKHOUSE_PASSWORD,
            "--query", export_query,
        ]

        with gzip.open(output_path, "wt") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                raise Exception(f"Export failed: {result.stderr}")

        size_bytes = output_path.stat().st_size

        return {
            "status": "completed",
            "rows": row_count,
            "size_bytes": size_bytes,
            "output_file": str(output_path),
        }

    def _create_checksum(self):
        """Create SHA256 checksum of all backup files."""
        checksums = {}
        for file_path in self.backup_path.rglob("*"):
            if file_path.is_file() and file_path.name != "checksums.json":
                sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                checksums[str(file_path.relative_to(self.backup_path))] = sha256.hexdigest()

        checksum_path = self.backup_path / "checksums.json"
        with open(checksum_path, "w") as f:
            json.dump(checksums, f, indent=2)

    def _compress_backup(self) -> Path:
        """Compress the entire backup directory."""
        archive_name = f"{self.backup_name}.tar.gz"
        archive_path = self.backup_dir / archive_name

        cmd = ["tar", "-czf", str(archive_path), "-C", str(self.backup_dir), self.backup_name]
        subprocess.run(cmd, check=True)

        # Remove uncompressed directory
        shutil.rmtree(self.backup_path)

        return archive_path

    def _upload_to_s3(self, archive_path: Path):
        """Upload backup archive to S3-compatible storage."""
        if not shutil.which("aws"):
            logger.warning("aws_cli_not_found", message="Install awscli for S3 upload")
            return

        s3_key = f"backups/clickhouse/{archive_path.name}"
        cmd = [
            "aws", "s3", "cp",
            str(archive_path),
            f"s3://{S3_BUCKET}/{s3_key}",
            "--endpoint-url", S3_ENDPOINT,
        ]

        if S3_ACCESS_KEY and S3_SECRET_KEY:
            env = os.environ.copy()
            env["AWS_ACCESS_KEY_ID"] = S3_ACCESS_KEY
            env["AWS_SECRET_ACCESS_KEY"] = S3_SECRET_KEY
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("backup_uploaded_to_s3", bucket=S3_BUCKET, key=s3_key)
        else:
            logger.warning("s3_upload_failed", error=result.stderr)

    def restore_backup(self, archive_path: Path, tables: Optional[List[str]] = None):
        """
        Restore a backup from archive.
        """
        tables = tables or TABLES

        if not archive_path.exists():
            raise FileNotFoundError(f"Backup archive not found: {archive_path}")

        logger.info("restore_started", archive=str(archive_path), tables=tables)

        # Extract archive
        extract_dir = self.backup_dir / "restore_temp"
        extract_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["tar", "-xzf", str(archive_path), "-C", str(extract_dir)]
        subprocess.run(cmd, check=True)

        # Find backup directory
        backup_dirs = list(extract_dir.iterdir())
        if not backup_dirs:
            raise Exception("No backup directory found in archive")
        backup_content = backup_dirs[0]

        # Verify checksums
        self._verify_checksums(backup_content)

        # Restore each table
        for table in tables:
            table_file = backup_content / f"{table}.tsv.gz"
            if not table_file.exists():
                logger.warning("table_file_not_found", table=table)
                continue

            try:
                self._restore_table(table, table_file)
                logger.info("table_restored", table=table)
            except Exception as e:
                logger.error("table_restore_failed", table=table, error=str(e))

        # Cleanup
        shutil.rmtree(extract_dir)

        logger.info("restore_completed")

    def _restore_table(self, table_name: str, data_file: Path):
        """Restore a single table from backup file."""
        # Truncate existing table
        truncate_query = f"TRUNCATE TABLE IF EXISTS {CLICKHOUSE_DATABASE}.{table_name}"
        self._clickhouse_query(truncate_query)

        # Import data
        import_query = (
            f"INSERT INTO {CLICKHOUSE_DATABASE}.{table_name} "
            f"FORMAT TSV"
        )

        cmd = [
            "clickhouse-client",
            "--host", CLICKHOUSE_HOST,
            "--port", CLICKHOUSE_PORT,
            "--user", CLICKHOUSE_USER,
            "--password", CLICKHOUSE_PASSWORD,
            "--query", import_query,
        ]

        with gzip.open(data_file, "rt") as f:
            result = subprocess.run(cmd, stdin=f, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Import failed: {result.stderr}")

    def _verify_checksums(self, backup_dir: Path):
        """Verify backup file integrity using checksums."""
        checksum_file = backup_dir / "checksums.json"
        if not checksum_file.exists():
            logger.warning("checksums_not_found", message="Skipping integrity check")
            return

        with open(checksum_file) as f:
            expected_checksums = json.load(f)

        for rel_path, expected_hash in expected_checksums.items():
            file_path = backup_dir / rel_path
            if not file_path.exists():
                logger.error("file_missing_in_backup", file=rel_path)
                continue

            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)

            if sha256.hexdigest() != expected_hash:
                raise Exception(f"Checksum mismatch for {rel_path}")

        logger.info("checksums_verified", files=len(expected_checksums))

    def list_backups(self) -> List[Dict]:
        """List all available backups."""
        backups = []

        # Local backups
        for f in sorted(self.backup_dir.glob("cgs_backup_*.tar.gz"), reverse=True):
            stat = f.stat()
            backups.append({
                "name": f.name,
                "type": "local",
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "path": str(f),
            })

        # S3 backups
        if S3_BUCKET and shutil.which("aws"):
            try:
                cmd = [
                    "aws", "s3", "ls",
                    f"s3://{S3_BUCKET}/backups/clickhouse/",
                    "--endpoint-url", S3_ENDPOINT,
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 4:
                            backups.append({
                                "name": parts[3],
                                "type": "s3",
                                "size_bytes": int(parts[2]),
                                "created_at": f"{parts[0]} {parts[1]}",
                                "path": f"s3://{S3_BUCKET}/backups/clickhouse/{parts[3]}",
                            })
            except Exception as e:
                logger.warning("s3_list_failed", error=str(e))

        return backups

    def cleanup_old_backups(self, retention_days: int = RETENTION_DAYS):
        """Remove backups older than retention period."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        removed = 0

        for f in self.backup_dir.glob("cgs_backup_*.tar.gz"):
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                f.unlink()
                removed += 1
                logger.info("old_backup_removed", file=f.name, age_days=(datetime.now(timezone.utc) - mtime).days)

        # Cleanup S3
        if S3_BUCKET and shutil.which("aws"):
            try:
                cmd = [
                    "aws", "s3", "ls",
                    f"s3://{S3_BUCKET}/backups/clickhouse/",
                    "--endpoint-url", S3_ENDPOINT,
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 4:
                            date_str = f"{parts[0]} {parts[1]}"
                            try:
                                backup_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                                backup_date = backup_date.replace(tzinfo=timezone.utc)
                                if backup_date < cutoff:
                                    key = f"backups/clickhouse/{parts[3]}"
                                    del_cmd = [
                                        "aws", "s3", "rm",
                                        f"s3://{S3_BUCKET}/{key}",
                                        "--endpoint-url", S3_ENDPOINT,
                                    ]
                                    subprocess.run(del_cmd, capture_output=True)
                                    removed += 1
                            except ValueError:
                                pass
            except Exception as e:
                logger.warning("s3_cleanup_failed", error=str(e))

        logger.info("cleanup_completed", removed=removed, retention_days=retention_days)
        return removed


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="ClickHouse Backup & Restore Tool")
    parser.add_argument("action", choices=["backup", "restore", "list", "cleanup"],
                       help="Action to perform")
    parser.add_argument("--tables", nargs="+", help="Specific tables to backup/restore")
    parser.add_argument("--archive", help="Backup archive path (for restore)")
    parser.add_argument("--retention", type=int, default=RETENTION_DAYS,
                       help="Retention days for cleanup")

    args = parser.parse_args()
    backup = ClickHouseBackup()

    if args.action == "backup":
        result = backup.create_backup(tables=args.tables)
        print(json.dumps(result, indent=2))

    elif args.action == "restore":
        if not args.archive:
            print("Error: --archive is required for restore", file=sys.stderr)
            sys.exit(1)
        backup.restore_backup(Path(args.archive), tables=args.tables)

    elif args.action == "list":
        backups = backup.list_backups()
        print(json.dumps(backups, indent=2))

    elif args.action == "cleanup":
        removed = backup.cleanup_old_backups(retention_days=args.retention)
        print(f"Removed {removed} old backups")


if __name__ == "__main__":
    main()
