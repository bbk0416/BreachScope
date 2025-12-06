"""
데이터 저장소 모듈
SQLite 기반 영구 저장 및 인덱싱을 제공합니다.
"""
import sqlite3
import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import hashlib

from .schemas import Event, Finding, EventChain, Scenario


class BreachScopeDB:
    """BreachScope 데이터베이스 관리"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """데이터베이스 초기화 및 테이블 생성"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()

        # Events 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                source TEXT NOT NULL,
                event_id TEXT,
                level TEXT,
                user TEXT,
                command_line TEXT,
                raw_data TEXT,
                event_hash TEXT UNIQUE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Findings 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                mitre_technique TEXT,
                event_id INTEGER,
                matched_value TEXT,
                matched_context TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        """)

        # Chains 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT UNIQUE NOT NULL,
                chain_type TEXT,
                description TEXT,
                confidence REAL,
                start_time TEXT,
                end_time TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Chain Events (다대다 관계)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chain_events (
                chain_id TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                FOREIGN KEY (chain_id) REFERENCES chains(chain_id),
                FOREIGN KEY (event_id) REFERENCES events(id),
                PRIMARY KEY (chain_id, event_id)
            )
        """)

        # Scenarios 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scenarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                attack_stage TEXT,
                confidence REAL,
                mitre_techniques TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Scenario Chains (다대다 관계)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scenario_chains (
                scenario_id TEXT NOT NULL,
                chain_id TEXT NOT NULL,
                FOREIGN KEY (scenario_id) REFERENCES scenarios(scenario_id),
                FOREIGN KEY (chain_id) REFERENCES chains(chain_id),
                PRIMARY KEY (scenario_id, chain_id)
            )
        """)

        # 인덱스 생성
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_mitre ON findings(mitre_technique)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chains_type ON chains(chain_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scenarios_stage ON scenarios(attack_stage)")

        self.conn.commit()

    def _calculate_event_hash(self, event: Event) -> str:
        """이벤트의 해시값 계산 (중복 방지)"""
        key = f"{event.timestamp}|{event.host}|{event.source}|{event.event_id}|{event.command_line}"
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def store_events(self, events: List[Event]) -> Dict[int, int]:
        """이벤트 저장 (event_hash로 중복 방지)"""
        cursor = self.conn.cursor()
        event_id_map: Dict[int, int] = {}  # 원본 인덱스 -> DB ID

        for idx, event in enumerate(events):
            event_hash = self._calculate_event_hash(event)

            # 중복 확인
            cursor.execute("SELECT id FROM events WHERE event_hash = ?", (event_hash,))
            existing = cursor.fetchone()

            if existing:
                event_id_map[idx] = existing['id']
                continue

            # 새 이벤트 삽입
            cursor.execute("""
                INSERT INTO events (
                    timestamp, host, source, event_id, level, user, command_line, raw_data, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp,
                event.host,
                event.source,
                event.event_id,
                event.level,
                event.user,
                event.command_line,
                json.dumps(event.raw, ensure_ascii=False),
                event_hash,
            ))

            event_id = cursor.lastrowid
            event_id_map[idx] = event_id

        self.conn.commit()
        return event_id_map

    def store_findings(self, findings: List[Finding], event_id_map: Dict[int, int], events: List[Event]):
        """탐지 결과 저장"""
        cursor = self.conn.cursor()

        # 이벤트 -> 인덱스 매핑 생성
        event_to_idx: Dict[Event, int] = {}
        for idx, event in enumerate(events):
            event_to_idx[event] = idx

        for finding in findings:
            # Finding의 이벤트로부터 인덱스 찾기
            event_idx = event_to_idx.get(finding.event)
            db_event_id = event_id_map.get(event_idx) if event_idx is not None else None

            cursor.execute("""
                INSERT INTO findings (
                    rule_id, rule_name, severity, mitre_technique, event_id, matched_value, matched_context
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.rule_id,
                finding.rule_name,
                finding.severity,
                finding.mitre_technique,
                db_event_id,
                finding.matched_value,
                finding.matched_context,
            ))

        self.conn.commit()

    def store_chains(self, chains: List[EventChain], event_id_map: Dict[int, int], events: List[Event]):
        """이벤트 체인 저장"""
        cursor = self.conn.cursor()

        # 이벤트 -> 인덱스 매핑 생성
        event_to_idx: Dict[Event, int] = {}
        for idx, event in enumerate(events):
            event_to_idx[event] = idx

        for chain in chains:
            cursor.execute("""
                INSERT OR REPLACE INTO chains (
                    chain_id, chain_type, description, confidence, start_time, end_time
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                chain.chain_id,
                chain.chain_type,
                chain.description,
                chain.confidence,
                chain.start_time,
                chain.end_time,
            ))

            # Chain-Events 관계 저장
            for event in chain.events:
                event_idx = event_to_idx.get(event)
                db_event_id = event_id_map.get(event_idx) if event_idx is not None else None
                if db_event_id:
                    cursor.execute("""
                        INSERT OR IGNORE INTO chain_events (chain_id, event_id)
                        VALUES (?, ?)
                    """, (chain.chain_id, db_event_id))

        self.conn.commit()

    def store_scenarios(self, scenarios: List[Scenario]):
        """시나리오 저장"""
        cursor = self.conn.cursor()

        for scenario in scenarios:
            cursor.execute("""
                INSERT OR REPLACE INTO scenarios (
                    scenario_id, name, description, attack_stage, confidence, mitre_techniques
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scenario.scenario_id,
                scenario.name,
                scenario.description,
                scenario.attack_stage,
                scenario.confidence,
                json.dumps(scenario.mitre_techniques, ensure_ascii=False),
            ))

            # Scenario-Chains 관계 저장
            for chain in scenario.chains:
                cursor.execute("""
                    INSERT OR IGNORE INTO scenario_chains (scenario_id, chain_id)
                    VALUES (?, ?)
                """, (scenario.scenario_id, chain.chain_id))

        self.conn.commit()

    def query_events(
        self,
        host: Optional[str] = None,
        source: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """이벤트 쿼리"""
        cursor = self.conn.cursor()
        conditions = []
        params = []

        if host:
            conditions.append("host = ?")
            params.append(host)
        if source:
            conditions.append("source = ?")
            params.append(source)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"""
            SELECT * FROM events
            WHERE {where_clause}
            ORDER BY timestamp
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    def query_findings(
        self,
        severity: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """탐지 결과 쿼리"""
        cursor = self.conn.cursor()
        conditions = []
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if mitre_technique:
            conditions.append("mitre_technique = ?")
            params.append(mitre_technique)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"""
            SELECT f.*, e.timestamp, e.host, e.source, e.command_line
            FROM findings f
            LEFT JOIN events e ON f.event_id = e.id
            WHERE {where_clause}
            ORDER BY f.created_at DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    def get_statistics(self) -> Dict[str, Any]:
        """데이터베이스 통계"""
        cursor = self.conn.cursor()

        stats = {}

        cursor.execute("SELECT COUNT(*) as count FROM events")
        stats["total_events"] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM findings")
        stats["total_findings"] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM chains")
        stats["total_chains"] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM scenarios")
        stats["total_scenarios"] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(DISTINCT host) as count FROM events")
        stats["unique_hosts"] = cursor.fetchone()['count']

        return stats

    def close(self):
        """데이터베이스 연결 종료"""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
