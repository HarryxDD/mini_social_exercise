"""Utility script to create the `reports` table for the mini_social_exercise app.

Usage:
    python create_reports_table.py            # uses database.sqlite in this folder
    python create_reports_table.py --db path/to/database.sqlite

Run this once (or as needed) to create the table. The Flask app will not try to create the table on startup.
"""

import sqlite3
import argparse
import os
import sys

CREATE_SQL = '''
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    reporter_id INTEGER NOT NULL,
    reason TEXT,
    status TEXT DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
'''


def ensure_reports_table(db_path: str) -> None:
    if not os.path.exists(db_path):
        print(f"Warning: database file '{db_path}' does not exist. The script will still attempt to create the table and will create the file if the directory is writable.")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(CREATE_SQL)
        conn.commit()
        print(f"Reports table ensured in database: {db_path}")
    except Exception as e:
        print(f"Failed to create reports table: {e}")
        raise
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create reports table for mini_social_exercise')
    parser.add_argument('--db', default='database.sqlite', help='Path to SQLite database file')
    args = parser.parse_args()

    try:
        ensure_reports_table(args.db)
    except Exception:
        sys.exit(1)
