"""
고급 디코더 모듈
PowerShell 난독화 해제, VBA 디스크램블, 문자열 치환 난독화 등을 지원합니다.
"""
import base64
import re
from typing import Optional, Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


def maybe_base64(s: str) -> Optional[str]:
    """Base64 디코딩 시도 (UTF-8, UTF-16LE 지원)"""
    t = s.strip()
    if len(t) < 8:
        return None
    try:
        data = base64.b64decode(t, validate=True)
    except Exception:
        return None
    # Try UTF-8 then UTF-16LE (common for PowerShell)
    for enc in ("utf-8", "utf-16le", "utf-16"):
        try:
            dec = data.decode(enc)
            if dec.strip():
                return dec
        except Exception:
            continue
    return None


def rot(s: str, n: int) -> str:
    """ROT13/ROTN 디코딩"""
    def rot_char(c: str) -> str:
        if "a" <= c <= "z":
            return chr((ord(c) - 97 + n) % 26 + 97)
        if "A" <= c <= "Z":
            return chr((ord(c) - 65 + n) % 26 + 65)
        return c
    return "".join(rot_char(c) for c in s)


def xor(s: str, key: int) -> str:
    """XOR 디코딩"""
    return "".join(chr(ord(c) ^ key) for c in s)


def decode_powershell_obfuscation(script: str) -> Dict[str, any]:
    """
    PowerShell 난독화 해제

    지원하는 난독화 기법:
    - Base64 인코딩
    - 문자열 치환 (변수명 난독화)
    - 압축 (Gzip/Deflate)
    - 인코딩 체인 (Base64 -> UTF-16LE 등)

    Returns:
        {
            "decoded": 디코딩된 스크립트,
            "techniques": 사용된 난독화 기법 목록,
            "confidence": 신뢰도 (0.0-1.0)
        }
    """
    techniques = []
    decoded = script
    confidence = 0.0

    # 1. Base64 디코딩 (반복 가능)
    max_iterations = 5
    for i in range(max_iterations):
        base64_decoded = maybe_base64(decoded)
        if base64_decoded and base64_decoded != decoded:
            decoded = base64_decoded
            techniques.append(f"Base64 디코딩 (반복 {i+1})")
            confidence += 0.2

    # 2. PowerShell 압축 해제 (Gzip/Deflate)
    # PowerShell에서 자주 사용되는 압축 패턴
    gzip_patterns = [
        r'\[IO\.Compression\.CompressionMode\]::Decompress',
        r'GzipStream',
        r'DeflateStream',
    ]
    for pattern in gzip_patterns:
        if re.search(pattern, decoded, re.IGNORECASE):
            techniques.append("압축 해제 감지")
            confidence += 0.1

    # 3. 문자열 치환 난독화 감지 및 해제 시도
    # 예: $var1 = 'Invoke'; $var2 = 'Expression'; & ($var1+$var2)
    substitution_pattern = r'\$(\w+)\s*=\s*[\'"]([^\'"]+)[\'"]'
    substitutions = re.findall(substitution_pattern, decoded)
    if substitutions:
        techniques.append("문자열 치환 난독화 감지")
        confidence += 0.15

        # 치환 변수 맵 생성
        var_map = {var: value for var, value in substitutions}

        # 변수 사용 패턴 찾기 및 치환 시도
        for var, value in var_map.items():
            # $var 또는 ${var} 패턴
            var_pattern = r'\$\{?' + re.escape(var) + r'\}?'
            decoded = re.sub(var_pattern, f'"{value}"', decoded)

    # 4. 인코딩 체인 감지
    # [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(...))
    encoding_patterns = [
        r'\[System\.Text\.Encoding\]::\w+\.GetString',
        r'\[System\.Convert\]::FromBase64String',
    ]
    for pattern in encoding_patterns:
        if re.search(pattern, decoded, re.IGNORECASE):
            techniques.append("인코딩 체인 감지")
            confidence += 0.1

    # 5. IEX (Invoke-Expression) 패턴 감지
    if re.search(r'IEX\s*\(|Invoke-Expression', decoded, re.IGNORECASE):
        techniques.append("IEX 패턴 감지")
        confidence += 0.1

    confidence = min(confidence, 1.0)

    return {
        "decoded": decoded,
        "techniques": techniques,
        "confidence": confidence,
        "original_length": len(script),
        "decoded_length": len(decoded),
    }


def decode_vba_obfuscation(vba_code: str) -> Dict[str, any]:
    """
    VBA 난독화 해제 (디스크램블)

    지원하는 난독화 기법:
    - 문자열 치환
    - 문자 코드 변환 (Chr 함수)
    - 변수명 난독화

    Returns:
        {
            "decoded": 디코딩된 코드,
            "techniques": 사용된 난독화 기법 목록,
            "confidence": 신뢰도 (0.0-1.0)
        }
    """
    techniques = []
    decoded = vba_code
    confidence = 0.0

    # 1. Chr() 함수를 실제 문자로 변환
    # 예: Chr(65) -> "A"
    chr_pattern = r'Chr\((\d+)\)'
    def replace_chr(match):
        try:
            char_code = int(match.group(1))
            if 0 <= char_code <= 255:
                return f'"{chr(char_code)}"'
        except:
            pass
        return match.group(0)

    if re.search(chr_pattern, decoded, re.IGNORECASE):
        decoded = re.sub(chr_pattern, replace_chr, decoded, flags=re.IGNORECASE)
        techniques.append("Chr() 함수 디코딩")
        confidence += 0.3

    # 2. ChrW() 함수 (유니코드)
    chrw_pattern = r'ChrW\((\d+)\)'
    def replace_chrw(match):
        try:
            char_code = int(match.group(1))
            if 0 <= char_code <= 65535:
                return f'"{chr(char_code)}"'
        except:
            pass
        return match.group(0)

    if re.search(chrw_pattern, decoded, re.IGNORECASE):
        decoded = re.sub(chrw_pattern, replace_chrw, decoded, flags=re.IGNORECASE)
        techniques.append("ChrW() 함수 디코딩")
        confidence += 0.2

    # 3. 문자열 연결 해제
    # 예: "Invoke" & "Expression" -> "InvokeExpression"
    concat_pattern = r'["\']([^"\']+)["\']\s*&\s*["\']([^"\']+)["\']'
    def replace_concat(match):
        return f'"{match.group(1)}{match.group(2)}"'

    if re.search(concat_pattern, decoded):
        decoded = re.sub(concat_pattern, replace_concat, decoded)
        techniques.append("문자열 연결 해제")
        confidence += 0.2

    # 4. 변수명 치환 감지
    # 예: Dim var1 As String: var1 = "cmd"
    dim_pattern = r'Dim\s+(\w+)\s+As\s+\w+.*?=\s*["\']([^"\']+)["\']'
    substitutions = re.findall(dim_pattern, decoded, re.IGNORECASE | re.DOTALL)
    if substitutions:
        techniques.append("변수명 치환 감지")
        confidence += 0.15

        # 변수 치환 시도
        for var, value in substitutions:
            var_pattern = r'\b' + re.escape(var) + r'\b'
            decoded = re.sub(var_pattern, f'"{value}"', decoded)

    confidence = min(confidence, 1.0)

    return {
        "decoded": decoded,
        "techniques": techniques,
        "confidence": confidence,
        "original_length": len(vba_code),
        "decoded_length": len(decoded),
    }


def decode_string_substitution(text: str) -> Dict[str, any]:
    """
    일반 문자열 치환 난독화 해제

    지원하는 패턴:
    - 단순 치환 (예: "a" -> "b")
    - ROT13/ROTN
    - XOR

    Returns:
        {
            "decoded": 디코딩된 텍스트,
            "techniques": 사용된 난독화 기법 목록,
            "confidence": 신뢰도 (0.0-1.0)
        }
    """
    techniques = []
    decoded = text
    confidence = 0.0

    # 1. ROT13 시도
    rot13_decoded = rot(text, 13)
    if rot13_decoded != text and len(rot13_decoded) > 0:
        # ROT13이 의미있는 결과를 생성했는지 간단히 확인
        # (실제로는 더 정교한 검증 필요)
        decoded = rot13_decoded
        techniques.append("ROT13 디코딩")
        confidence += 0.3

    # 2. XOR 시도 (일반적인 키 값들)
    common_xor_keys = [1, 2, 3, 5, 7, 13, 42, 255]
    for key in common_xor_keys:
        xor_decoded = xor(text, key)
        # XOR 결과가 인쇄 가능한 문자인지 확인
        if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in xor_decoded[:100]):
            if xor_decoded != text:
                decoded = xor_decoded
                techniques.append(f"XOR 디코딩 (키: {key})")
                confidence += 0.2
                break

    confidence = min(confidence, 1.0)

    return {
        "decoded": decoded,
        "techniques": techniques,
        "confidence": confidence,
        "original_length": len(text),
        "decoded_length": len(decoded),
    }


def identify_malicious_behavior(decoded_text: str) -> List[Dict[str, any]]:
    """
    복호화된 명령어에서 악성 행위 식별

    IOC 패턴 및 MITRE ATT&CK 매핑을 사용하여 행위를 식별합니다.

    Returns:
        악성 행위 목록 (각 항목은 technique, description, confidence 포함)
    """
    behaviors = []

    # MITRE ATT&CK 기법 매핑
    ioc_patterns = {
        "T1059.001": {  # PowerShell
            "patterns": [
                r'Invoke-Mimikatz',
                r'Invoke-ReflectivePEInjection',
                r'DownloadString',
                r'DownloadFile',
                r'IEX\s*\(',
            ],
            "description": "PowerShell을 통한 명령 및 스크립트 인터프리터",
        },
        "T1059.003": {  # Windows Command Shell
            "patterns": [
                r'cmd\.exe\s+/c',
                r'cmd\.exe\s+/k',
                r'powershell.*-enc',
            ],
            "description": "Windows 명령 셸",
        },
        "T1003": {  # OS Credential Dumping
            "patterns": [
                r'Mimikatz',
                r'lsadump',
                r'sekurlsa',
                r'wdigest',
                r'kerberos',
            ],
            "description": "OS 자격증명 덤프",
        },
        "T1071": {  # Application Layer Protocol
            "patterns": [
                r'http[s]?://',
                r'WebClient\.DownloadString',
                r'WebClient\.DownloadFile',
                r'Net\.WebClient',
            ],
            "description": "애플리케이션 계층 프로토콜",
        },
        "T1105": {  # Ingress Tool Transfer
            "patterns": [
                r'DownloadString',
                r'DownloadFile',
                r'Invoke-WebRequest',
                r'wget',
                r'curl',
            ],
            "description": "도구 전송",
        },
        "T1083": {  # File and Directory Discovery
            "patterns": [
                r'Get-ChildItem',
                r'dir\s+/s',
                r'ls\s+-R',
            ],
            "description": "파일 및 디렉토리 탐색",
        },
        "T1055": {  # Process Injection
            "patterns": [
                r'VirtualAlloc',
                r'CreateRemoteThread',
                r'WriteProcessMemory',
            ],
            "description": "프로세스 주입",
        },
    }

    decoded_lower = decoded_text.lower()

    for technique_id, ioc_data in ioc_patterns.items():
        for pattern in ioc_data["patterns"]:
            if re.search(pattern, decoded_lower, re.IGNORECASE):
                behaviors.append({
                    "technique": technique_id,
                    "description": ioc_data["description"],
                    "pattern": pattern,
                    "confidence": 0.8,  # 패턴 매칭 시 기본 신뢰도
                })
                break  # 한 기법당 하나의 매칭만 기록

    return behaviors


def decode_all(text: str, text_type: str = "auto") -> Dict[str, any]:
    """
    모든 디코딩 기법을 시도하여 최적의 결과 반환

    Args:
        text: 디코딩할 텍스트
        text_type: 텍스트 타입 ("powershell", "vba", "string", "auto")

    Returns:
        디코딩 결과 및 메타데이터
    """
    results = []

    if text_type == "auto":
        # 자동 감지
        text_lower = text.lower()
        if "sub " in text_lower or "function " in text_lower or "dim " in text_lower:
            text_type = "vba"
        elif "powershell" in text_lower or "invoke-" in text_lower or "$" in text:
            text_type = "powershell"
        else:
            text_type = "string"

    # 타입별 디코딩 시도
    if text_type == "powershell":
        result = decode_powershell_obfuscation(text)
        results.append(result)
    elif text_type == "vba":
        result = decode_vba_obfuscation(text)
        results.append(result)
    else:
        result = decode_string_substitution(text)
        results.append(result)

    # 추가로 일반 디코딩도 시도
    if text_type != "string":
        string_result = decode_string_substitution(text)
        if string_result["confidence"] > 0:
            results.append(string_result)

    # 가장 높은 신뢰도의 결과 선택
    best_result = max(results, key=lambda x: x["confidence"])

    # 악성 행위 식별
    behaviors = identify_malicious_behavior(best_result["decoded"])

    return {
        **best_result,
        "text_type": text_type,
        "behaviors": behaviors,
        "all_results": results,
    }
