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

        # 성능 최적화 설정
        # WAL 모드 활성화 (Write-Ahead Logging) - 동시성 및 성능 향상
        self.conn.execute("PRAGMA journal_mode=WAL")
        # 동기화 모드 설정 (NORMAL은 WAL 모드에서 권장)
        self.conn.execute("PRAGMA synchronous=NORMAL")
        # 페이지 크기 최적화 (4096은 대부분의 시스템에 적합)
        self.conn.execute("PRAGMA page_size=4096")
        # 캐시 크기 설정 (100MB)
        self.conn.execute("PRAGMA cache_size=-25600")  # 100MB (25600 * 4KB)
        # 외래 키 제약 조건 활성화
        self.conn.execute("PRAGMA foreign_keys=ON")

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
        # 복합 인덱스 추가 (자주 함께 쿼리되는 컬럼)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_host_timestamp ON events(host, timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_timestamp ON events(source, timestamp)")
        # event_hash 인덱스 (중복 확인 최적화)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_mitre ON findings(mitre_technique)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_event_id ON findings(event_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chains_type ON chains(chain_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scenarios_stage ON scenarios(attack_stage)")

        self.conn.commit()

    def _calculate_event_hash(self, event: Event) -> str:
        """이벤트의 해시값 계산 (중복 방지)"""
        key = f"{event.timestamp}|{event.host}|{event.source}|{event.event_id}|{event.command_line}"
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def store_events(self, events: List[Event], batch_size: int = 1000) -> Dict[int, int]:
        """
        이벤트 저장 (event_hash로 중복 방지, 배치 처리로 성능 최적화)

        Args:
            events: 저장할 이벤트 목록
            batch_size: 배치 크기 (기본 1000)

        Returns:
            원본 인덱스 -> DB ID 매핑
        """
        if not events:
            return {}

        cursor = self.conn.cursor()
        event_id_map: Dict[int, int] = {}  # 원본 인덱스 -> DB ID

        # 1단계: 모든 이벤트의 해시 계산
        event_hashes = [self._calculate_event_hash(event) for event in events]

        # 2단계: 배치로 중복 확인 (IN 절 사용)
        existing_hashes: Dict[str, int] = {}  # hash -> id
        for i in range(0, len(event_hashes), batch_size):
            batch_hashes = event_hashes[i:i + batch_size]
            placeholders = ','.join(['?'] * len(batch_hashes))
            cursor.execute(
                f"SELECT id, event_hash FROM events WHERE event_hash IN ({placeholders})",
                batch_hashes
            )
            for row in cursor.fetchall():
                existing_hashes[row['event_hash']] = row['id']

        # 3단계: 새 이벤트만 배치 삽입
        new_events_data = []
        new_events_indices = []  # 원본 인덱스 저장

        for idx, (event, event_hash) in enumerate(zip(events, event_hashes)):
            if event_hash in existing_hashes:
                event_id_map[idx] = existing_hashes[event_hash]
            else:
                new_events_indices.append(idx)
                new_events_data.append((
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

        # 배치 삽입 실행
        if new_events_data:
            insert_sql = """
                INSERT INTO events (
                    timestamp, host, source, event_id, level, user, command_line, raw_data, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            # executemany 사용 (배치 삽입)
            cursor.executemany(insert_sql, new_events_data)

            # 삽입된 이벤트의 해시로 ID 조회 (배치 조회)
            if new_events_indices:
                new_hashes = [event_hashes[idx] for idx in new_events_indices]
                placeholders = ','.join(['?'] * len(new_hashes))
                cursor.execute(
                    f"SELECT id, event_hash FROM events WHERE event_hash IN ({placeholders})",
                    new_hashes
                )
                hash_to_id = {row['event_hash']: row['id'] for row in cursor.fetchall()}

                # 인덱스 매핑
                for orig_idx, event_hash in zip(new_events_indices, new_hashes):
                    event_id_map[orig_idx] = hash_to_id.get(event_hash)

        # 배치 커밋
        self.conn.commit()
        return event_id_map

    def store_findings(self, findings: List[Finding], event_id_map: Dict[int, int], events: List[Event], batch_size: int = 1000):
        """
        탐지 결과 저장 (배치 처리로 성능 최적화)

        Args:
            findings: 저장할 탐지 결과 목록
            event_id_map: 이벤트 인덱스 -> DB ID 매핑
            events: 이벤트 목록
            batch_size: 배치 크기 (기본 1000)
        """
        if not findings:
            return

        cursor = self.conn.cursor()

        # 이벤트 -> 인덱스 매핑 생성
        event_to_idx: Dict[Event, int] = {}
        for idx, event in enumerate(events):
            event_to_idx[event] = idx

        # 배치 삽입을 위한 데이터 준비
        findings_data = []
        for finding in findings:
            # Finding의 이벤트로부터 인덱스 찾기
            event_idx = event_to_idx.get(finding.event)
            db_event_id = event_id_map.get(event_idx) if event_idx is not None else None

            findings_data.append((
                finding.rule_id,
                finding.rule_name,
                finding.severity,
                finding.mitre_technique,
                db_event_id,
                finding.matched_value,
                finding.matched_context,
            ))

        # 배치 삽입 실행
        insert_sql = """
            INSERT INTO findings (
                rule_id, rule_name, severity, mitre_technique, event_id, matched_value, matched_context
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        cursor.executemany(insert_sql, findings_data)
        self.conn.commit()

    def store_chains(self, chains: List[EventChain], event_id_map: Dict[int, int], events: List[Event]):
        """
        이벤트 체인 저장 (배치 처리로 성능 최적화)

        Args:
            chains: 저장할 체인 목록
            event_id_map: 이벤트 인덱스 -> DB ID 매핑
            events: 이벤트 목록
        """
        if not chains:
            return

        cursor = self.conn.cursor()

        # 이벤트 -> 인덱스 매핑 생성
        event_to_idx: Dict[Event, int] = {}
        for idx, event in enumerate(events):
            event_to_idx[event] = idx

        # 체인 데이터 준비
        chains_data = []
        chain_events_data = []

        for chain in chains:
            chains_data.append((
                chain.chain_id,
                chain.chain_type,
                chain.description,
                chain.confidence,
                chain.start_time,
                chain.end_time,
            ))

            # Chain-Events 관계 데이터 준비
            for event in chain.events:
                event_idx = event_to_idx.get(event)
                db_event_id = event_id_map.get(event_idx) if event_idx is not None else None
                if db_event_id:
                    chain_events_data.append((chain.chain_id, db_event_id))

        # 배치 삽입 실행
        if chains_data:
            cursor.executemany("""
                INSERT OR REPLACE INTO chains (
                    chain_id, chain_type, description, confidence, start_time, end_time
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, chains_data)

        if chain_events_data:
            cursor.executemany("""
                INSERT OR IGNORE INTO chain_events (chain_id, event_id)
                VALUES (?, ?)
            """, chain_events_data)

        self.conn.commit()

    def store_scenarios(self, scenarios: List[Scenario]):
        """
        시나리오 저장 (배치 처리로 성능 최적화)

        Args:
            scenarios: 저장할 시나리오 목록
        """
        if not scenarios:
            return

        cursor = self.conn.cursor()

        # 시나리오 데이터 준비
        scenarios_data = []
        scenario_chains_data = []

        for scenario in scenarios:
            scenarios_data.append((
                scenario.scenario_id,
                scenario.name,
                scenario.description,
                scenario.attack_stage,
                scenario.confidence,
                json.dumps(scenario.mitre_techniques, ensure_ascii=False),
            ))

            # Scenario-Chains 관계 데이터 준비
            for chain in scenario.chains:
                scenario_chains_data.append((scenario.scenario_id, chain.chain_id))

        # 배치 삽입 실행
        if scenarios_data:
            cursor.executemany("""
                INSERT OR REPLACE INTO scenarios (
                    scenario_id, name, description, attack_stage, confidence, mitre_techniques
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, scenarios_data)

        if scenario_chains_data:
            cursor.executemany("""
                INSERT OR IGNORE INTO scenario_chains (scenario_id, chain_id)
                VALUES (?, ?)
            """, scenario_chains_data)

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
