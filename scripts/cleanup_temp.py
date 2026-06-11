#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BreachScope 임시 파일 정리 스크립트
프로젝트 내 임시 디렉토리 및 파일을 정리합니다.

사용법:
    python scripts/cleanup_temp.py          # 대화형 모드
    python scripts/cleanup_temp.py --yes    # 자동 정리
    python scripts/cleanup_temp.py -y      # 자동 정리 (단축)
"""
import os
import shutil
import tempfile
from pathlib import Path
from typing import List


def find_temp_directories(project_root: Path) -> List[Path]:
    """프로젝트 내 임시 디렉토리 찾기"""
    temp_dirs = []

    # 프로젝트 루트에서 임시 디렉토리 패턴 검색
    patterns = [
        ".breachscope_temp",
        ".breachscope_web_temp",
        ".breachscope_collect_temp",
        "breachscope_evtx_*",
        "breachscope_collect_*",
        "bs_web_*",
    ]

    # 직접 패턴 매칭
    for item in project_root.iterdir():
        if item.is_dir():
            name = item.name
            if (name.startswith(".breachscope") or
                name.startswith("breachscope_evtx_") or
                name.startswith("breachscope_collect_") or
                name.startswith("bs_web_")):
                temp_dirs.append(item)

    # 재귀적으로 .breachscope_temp 찾기
    for item in project_root.rglob(".breachscope_temp"):
        if item.is_dir() and item not in temp_dirs:
            temp_dirs.append(item)

    return temp_dirs


def find_temp_files(project_root: Path) -> List[Path]:
    """프로젝트 내 임시 파일 찾기"""
    temp_files = []

    # .db 파일 (breachscope.db 제외)
    for db_file in project_root.rglob("*.db"):
        if db_file.name != "breachscope.db" or not (project_root / "breachscope.db").exists():
            temp_files.append(db_file)

    # .log 파일
    for log_file in project_root.rglob("*.log"):
        if log_file.parent.name != "docs":  # docs 내 로그는 제외
            temp_files.append(log_file)

    return temp_files


def cleanup_system_temp(project_name: str = "breachscope") -> List[Path]:
    """시스템 임시 디렉토리에서 BreachScope 관련 임시 파일 찾기"""
    cleaned = []
    temp_dir = Path(tempfile.gettempdir())

    # 시스템 임시 디렉토리에서 BreachScope 관련 디렉토리 찾기
    patterns = [
        f"bs_web_*",
        f"breachscope_evtx_*",
        f"breachscope_collect_*",
        f"{project_name}_*",
    ]

    if temp_dir.exists():
        for item in temp_dir.iterdir():
            if item.is_dir():
                name = item.name
                if (name.startswith("bs_web_") or
                    name.startswith("breachscope_evtx_") or
                    name.startswith("breachscope_collect_") or
                    (name.startswith(project_name + "_") and name != project_name)):
                    cleaned.append(item)

    return cleaned


def main():
    """메인 함수"""
    project_root = Path(__file__).parent.parent

    print("=" * 60)
    print("BreachScope 임시 파일 정리")
    print("=" * 60)

    # 프로젝트 내 임시 디렉토리
    temp_dirs = find_temp_directories(project_root)
    print(f"\n프로젝트 내 임시 디렉토리: {len(temp_dirs)}개")

    # 프로젝트 내 임시 파일
    temp_files = find_temp_files(project_root)
    print(f"프로젝트 내 임시 파일: {len(temp_files)}개")

    # 시스템 임시 디렉토리
    system_temp = cleanup_system_temp()
    print(f"시스템 임시 디렉토리: {len(system_temp)}개")

    total = len(temp_dirs) + len(temp_files) + len(system_temp)

    if total == 0:
        print("\n[OK] 정리할 임시 파일이 없습니다.")
        return

    print(f"\n총 {total}개 항목 발견")
    print("\n정리할 항목:")

    for d in temp_dirs:
        print(f"  - 디렉토리: {d.relative_to(project_root)}")

    for f in temp_files:
        print(f"  - 파일: {f.relative_to(project_root)}")

    for d in system_temp:
        print(f"  - 시스템 임시: {d}")

    # 자동 정리 모드 (비대화형 환경 지원)
    import sys
    auto_clean = "--yes" in sys.argv or "-y" in sys.argv

    if not auto_clean:
        try:
            response = input("\n정리하시겠습니까? (y/N): ").strip().lower()
            if response != 'y':
                print("취소되었습니다.")
                return
        except (EOFError, KeyboardInterrupt):
            print("\n비대화형 환경에서 자동 정리 모드로 실행합니다.")
            print("자동 정리하려면 --yes 또는 -y 옵션을 사용하세요.")
            auto_clean = True

    # 정리 실행
    cleaned_count = 0

    for d in temp_dirs:
        try:
            shutil.rmtree(d)
            print(f"[OK] 삭제: {d.relative_to(project_root)}")
            cleaned_count += 1
        except Exception as e:
            print(f"[FAIL] 삭제 실패: {d.relative_to(project_root)} - {e}")

    for f in temp_files:
        try:
            f.unlink()
            print(f"[OK] 삭제: {f.relative_to(project_root)}")
            cleaned_count += 1
        except Exception as e:
            print(f"[FAIL] 삭제 실패: {f.relative_to(project_root)} - {e}")

    for d in system_temp:
        try:
            shutil.rmtree(d)
            print(f"[OK] 삭제: {d}")
            cleaned_count += 1
        except Exception as e:
            print(f"[FAIL] 삭제 실패: {d} - {e}")

    print(f"\n[OK] 정리 완료: {cleaned_count}개 항목 삭제")


if __name__ == "__main__":
    main()
