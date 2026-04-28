"""
database.py - SQLite Database Module for PhishGuard Pro
Production-grade database with fallback JSON support.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import List, Dict, Optional, Any
import threading


class Database:
    """
    Hybrid database: SQLite primary, JSON fallback.
    Thread-safe singleton pattern.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = None, json_path: str = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: str = None, json_path: str = None):
        if self._initialized:
            return

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = db_path or os.path.join(base_dir, 'phishguard.db')
        self.json_path = json_path or os.path.join(base_dir, 'phishguard_db.json')
        self._local = threading.local()

        # Initialize SQLite
        self._init_sqlite()
        self._initialized = True

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    @contextmanager
    def _transaction(self):
        """Context manager for database transactions."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def _init_sqlite(self):
        """Create tables if they don't exist."""
        with self._transaction() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    result TEXT NOT NULL,
                    score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    verdict TEXT,
                    risk_level TEXT,
                    reasons TEXT,
                    ml_score REAL DEFAULT 0,
                    rule_score REAL DEFAULT 0,
                    api_score REAL DEFAULT 0,
                    hybrid_score REAL DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS corrections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    predicted_label INTEGER NOT NULL,
                    corrected_label INTEGER NOT NULL,
                    scan_id INTEGER,
                    notes TEXT,
                    processed INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS daily_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE NOT NULL,
                    total_scans INTEGER DEFAULT 0,
                    safe_count INTEGER DEFAULT 0,
                    suspicious_count INTEGER DEFAULT 0,
                    malicious_count INTEGER DEFAULT 0,
                    corrections_count INTEGER DEFAULT 0
                )
            ''')

            # Insert default settings
            defaults = [
                ('ml_enabled', '1'),
                ('threat_intel_enabled', '1'),
                ('auto_update', '1'),
                ('notification_email', ''),
                ('hybrid_scoring_enabled', '1'),
                ('feedback_learning_enabled', '1'),
                ('model_versioning_enabled', '1')
            ]
            conn.executemany('''
                INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)
            ''', defaults)

    # ==================== USERS ====================

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username. Matches app.py interface."""
        with self._transaction() as conn:
            cursor = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_user_count(self) -> int:
        """Get total user count. Used by setup route."""
        with self._transaction() as conn:
            cursor = conn.execute('SELECT COUNT(*) as count FROM users')
            return cursor.fetchone()['count']

    def create_user(self, username: str, password_hash: str) -> bool:
        """Create a new user."""
        try:
            with self._transaction() as conn:
                conn.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, password_hash)
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def update_user_password(self, username: str, password_hash: str) -> bool:
        """Update user password. Matches app.py interface."""
        with self._transaction() as conn:
            cursor = conn.execute(
                'UPDATE users SET password_hash = ? WHERE username = ?',
                (password_hash, username)
            )
            return cursor.rowcount > 0

    # ==================== SCANS ====================

    def add_scan(self, scan_data: Dict) -> int:
        """Add a new scan record. Returns scan ID."""
        url = scan_data.get('input', scan_data.get('url', ''))
        result = scan_data.get('result', scan_data.get('risk_level', 'UNKNOWN'))
        score = float(scan_data.get('score', 0))
        confidence = float(scan_data.get('confidence', 0))
        verdict = scan_data.get('verdict', '')
        risk_level = scan_data.get('risk_level', result)
        reasons = json.dumps(scan_data.get('reasons', [])) if isinstance(scan_data.get('reasons'), list) else str(scan_data.get('reasons', '[]'))

        # Hybrid scores - extract from component_scores if available
        component_scores = scan_data.get('component_scores', {})
        ml_score = float(component_scores.get('ml_score', 0))
        rule_score = float(component_scores.get('rule_score', 0))
        api_score = float(component_scores.get('api_score', 0))
        hybrid_score = float(scan_data.get('hybrid_score', 0))

        with self._transaction() as conn:
            cursor = conn.execute('''
                INSERT INTO scans 
                (url, result, score, confidence, verdict, risk_level, reasons, 
                 ml_score, rule_score, api_score, hybrid_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (url, result, score, confidence, verdict, risk_level, reasons,
                  ml_score, rule_score, api_score, hybrid_score,
                  scan_data.get('timestamp', datetime.now().isoformat())))

            scan_id = cursor.lastrowid

            # Update daily stats
            today = datetime.now().strftime('%Y-%m-%d')
            safe = 1 if risk_level in ['LOW', 'MINIMAL', 'Safe'] else 0
            suspicious = 1 if risk_level == 'MEDIUM' else 0
            malicious = 1 if risk_level in ['HIGH', 'Malicious'] else 0

            conn.execute('''
                INSERT INTO daily_stats (date, total_scans, safe_count, suspicious_count, malicious_count)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(date) DO UPDATE SET
                    total_scans = total_scans + 1,
                    safe_count = safe_count + ?,
                    suspicious_count = suspicious_count + ?,
                    malicious_count = malicious_count + ?
            ''', (today, safe, suspicious, malicious, safe, suspicious, malicious))

            return scan_id

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict]:
        """Get scan by ID."""
        with self._transaction() as conn:
            cursor = conn.execute(
                'SELECT * FROM scans WHERE id = ?', (scan_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_scan_by_url(self, url: str) -> Optional[Dict]:
        """Get most recent scan by URL. Matches app.py interface."""
        with self._transaction() as conn:
            cursor = conn.execute(
                'SELECT * FROM scans WHERE url = ? ORDER BY timestamp DESC LIMIT 1', (url,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_recent_scans(self, limit: int = 50) -> List[Dict]:
        """Get recent scans."""
        with self._transaction() as conn:
            cursor = conn.execute(
                'SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_scans_by_date_range(self, start_date: str, end_date: str) -> List[Dict]:
        """Get scans within date range."""
        with self._transaction() as conn:
            cursor = conn.execute(
                '''SELECT * FROM scans 
                   WHERE DATE(timestamp) BETWEEN ? AND ?
                   ORDER BY timestamp DESC''',
                (start_date, end_date)
            )
            return [dict(row) for row in cursor.fetchall()]

    def clear_scans(self) -> bool:
        """Clear all scan history."""
        with self._transaction() as conn:
            conn.execute('DELETE FROM scans')
            conn.execute('DELETE FROM daily_stats')
            return True

    # ==================== STATS ====================

    def get_stats(self) -> Dict:
        """Get scan statistics."""
        with self._transaction() as conn:
            cursor = conn.execute('SELECT COUNT(*) as total FROM scans')
            total = cursor.fetchone()['total']

            if total == 0:
                return {
                    'total': 0,
                    'safe': 0,
                    'suspicious': 0,
                    'malicious': 0,
                    'safe_pct': 0,
                    'suspicious_pct': 0,
                    'malicious_pct': 0
                }

            cursor = conn.execute('''
                SELECT 
                    SUM(CASE WHEN risk_level IN ('LOW', 'MINIMAL', 'Safe') THEN 1 ELSE 0 END) as safe,
                    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN risk_level IN ('HIGH', 'Malicious') THEN 1 ELSE 0 END) as malicious
                FROM scans
            ''')
            row = cursor.fetchone()

            safe = row['safe'] or 0
            suspicious = row['suspicious'] or 0
            malicious = row['malicious'] or 0

            return {
                'total': total,
                'safe': safe,
                'suspicious': suspicious,
                'malicious': malicious,
                'safe_pct': round(safe / total * 100, 1) if total > 0 else 0,
                'suspicious_pct': round(suspicious / total * 100, 1) if total > 0 else 0,
                'malicious_pct': round(malicious / total * 100, 1) if total > 0 else 0
            }

    def get_daily_stats(self, days: int = 30) -> List[Dict]:
        """Get daily statistics for charting."""
        with self._transaction() as conn:
            cursor = conn.execute('''
                SELECT * FROM daily_stats
                WHERE date >= date('now', '-{} days')
                ORDER BY date ASC
            '''.format(days))
            return [dict(row) for row in cursor.fetchall()]

    def get_scan_chart_data(self) -> Dict:
        """Get chart data for admin dashboard. Matches app.py interface."""
        # Pie chart data (overall distribution)
        stats = self.get_stats()
        pie_data = {
            'labels': ['Safe', 'Suspicious', 'Malicious'],
            'data': [stats['safe'], stats['suspicious'], stats['malicious']],
            'colors': ['#28a745', '#ffc107', '#dc3545']
        }

        # Line chart data (daily scans for last 30 days)
        daily = self.get_daily_stats(30)
        line_data = {
            'labels': [d['date'] for d in daily],
            'datasets': [
                {
                    'label': 'Total Scans',
                    'data': [d['total_scans'] for d in daily],
                    'borderColor': '#007bff',
                    'fill': False
                },
                {
                    'label': 'Safe',
                    'data': [d['safe_count'] for d in daily],
                    'borderColor': '#28a745',
                    'fill': False
                },
                {
                    'label': 'Suspicious',
                    'data': [d['suspicious_count'] for d in daily],
                    'borderColor': '#ffc107',
                    'fill': False
                },
                {
                    'label': 'Malicious',
                    'data': [d['malicious_count'] for d in daily],
                    'borderColor': '#dc3545',
                    'fill': False
                }
            ]
        }

        return {
            'pie': pie_data,
            'line': line_data,
            'stats': stats
        }

    # ==================== CORRECTIONS ====================

    def add_correction(self, url: str, predicted_label: int, corrected_label: int,
                       scan_id: int = None, notes: str = '') -> int:
        """Add a correction record."""
        with self._transaction() as conn:
            cursor = conn.execute('''
                INSERT INTO corrections (url, predicted_label, corrected_label, scan_id, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, predicted_label, corrected_label, scan_id, notes))

            correction_id = cursor.lastrowid

            # Update daily stats corrections count
            today = datetime.now().strftime('%Y-%m-%d')
            conn.execute('''
                INSERT INTO daily_stats (date, corrections_count)
                VALUES (?, 1)
                ON CONFLICT(date) DO UPDATE SET
                    corrections_count = corrections_count + 1
            ''', (today,))

            return correction_id

    def get_corrections(self, limit: int = 100) -> List[Dict]:
        """Get corrections. Matches app.py interface (limit as first positional arg)."""
        with self._transaction() as conn:
            cursor = conn.execute(
                '''SELECT c.*, s.url as scan_url, s.result as scan_result 
                   FROM corrections c
                   LEFT JOIN scans s ON c.scan_id = s.id
                   ORDER BY c.timestamp DESC LIMIT ?''',
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_all_corrections(self) -> List[Dict]:
        """Get all unprocessed corrections for retraining. Matches app.py interface."""
        with self._transaction() as conn:
            cursor = conn.execute(
                '''SELECT c.*, s.url as scan_url, s.result as scan_result 
                   FROM corrections c
                   LEFT JOIN scans s ON c.scan_id = s.id
                   WHERE c.processed = 0
                   ORDER BY c.timestamp DESC'''
            )
            return [dict(row) for row in cursor.fetchall()]

    def mark_corrections_as_used(self) -> bool:
        """Mark all unprocessed corrections as processed. Matches app.py interface."""
        with self._transaction() as conn:
            conn.execute('UPDATE corrections SET processed = 1 WHERE processed = 0')
            return True

    def clear_corrections(self) -> bool:
        """Clear all corrections. Matches app.py interface."""
        with self._transaction() as conn:
            conn.execute('DELETE FROM corrections')
            return True

    def get_correction_stats(self) -> Dict:
        """Get correction statistics."""
        with self._transaction() as conn:
            cursor = conn.execute('SELECT COUNT(*) as total FROM corrections')
            total = cursor.fetchone()['total']

            cursor = conn.execute('SELECT COUNT(*) as unprocessed FROM corrections WHERE processed = 0')
            unprocessed = cursor.fetchone()['unprocessed']

            cursor = conn.execute('''
                SELECT corrected_label, COUNT(*) as count 
                FROM corrections GROUP BY corrected_label
            ''')
            label_dist = {row['corrected_label']: row['count'] for row in cursor.fetchall()}

            return {
                'total': total,
                'unprocessed': unprocessed,
                'processed': total - unprocessed,
                'marked_safe': label_dist.get(0, 0),
                'marked_phishing': label_dist.get(1, 0)
            }

    # ==================== SETTINGS ====================

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        with self._transaction() as conn:
            cursor = conn.execute(
                'SELECT value FROM settings WHERE key = ?', (key,)
            )
            row = cursor.fetchone()
            if row:
                return row['value']
            return default

    def get_settings(self) -> Dict:
        """Get all settings."""
        with self._transaction() as conn:
            cursor = conn.execute('SELECT key, value FROM settings')
            return {row['key']: row['value'] for row in cursor.fetchall()}

    def set_setting(self, key: str, value: str) -> bool:
        """Set a setting value."""
        with self._transaction() as conn:
            conn.execute('''
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            ''', (key, value))
            return True

    def update_settings(self, settings_dict: Dict) -> bool:
        """Update multiple settings."""
        with self._transaction() as conn:
            for key, value in settings_dict.items():
                conn.execute('''
                    INSERT INTO settings (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
                ''', (key, str(value)))
            return True

    # ==================== JSON FALLBACK ====================

    def save_json_fallback(self):
        """Save current state to JSON as backup."""
        data = {
            'scans': self.get_recent_scans(1000),
            'corrections': self.get_corrections(1000),
            'settings': self.get_settings(),
            'stats': self.get_stats(),
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.json_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"JSON fallback save failed: {e}")

    def load_json_fallback(self) -> Dict:
        """Load data from JSON fallback."""
        if os.path.exists(self.json_path):
            try:
                with open(self.json_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"JSON fallback load failed: {e}")
        return {}

    def migrate_from_json(self):
        """Migrate data from old JSON format to SQLite."""
        if not os.path.exists(self.json_path):
            return

        try:
            with open(self.json_path, 'r') as f:
                data = json.load(f)

            # Migrate scans
            for scan in data.get('scans', []):
                try:
                    self.add_scan(scan)
                except Exception as e:
                    print(f"Failed to migrate scan: {e}")

            # Migrate settings
            for key, value in data.get('settings', {}).items():
                self.set_setting(key, str(value))

            print(f"Migration complete. Migrated {len(data.get('scans', []))} scans.")

        except Exception as e:
            print(f"Migration failed: {e}")


# Global instance
db = Database()