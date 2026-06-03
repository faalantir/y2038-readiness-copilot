from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Optional

from .models import Finding

TEXT_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".sql", ".proto", ".msg", ".idl", ".json", ".yaml", ".yml",
    ".toml", ".mk", ".cmake", ".txt", ".md", ".rst", ".gradle",
}

SPECIAL_NAMES = {
    "makefile", "cmakelists.txt", "dockerfile", "configure.ac", "configure.in",
    "meson.build", "build.gradle", "pom.xml", "package.json",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "build", "dist", "target", ".tox", ".pytest_cache", "__pycache__",
    "reports", ".idea", ".vscode",
}

# Match time-like words as tokens rather than substrings.
# This avoids obvious false positives such as "update" / "validate" containing "date".
TIME_WORD_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])"
    r"(time|timestamp|epoch|unix|expiry|expires|expired|expiration|expire|"
    r"last[_-]?seen|lastseen|created[_-]?at|updated[_-]?at|deleted[_-]?at|"
    r"boot[_-]?time|event[_-]?time|deadline|not[_-]?after|valid[_-]?until|date)"
    r"(?:$|[^A-Za-z0-9])",
    re.IGNORECASE,
)

ABSOLUTE_TIME_HINT_RE = re.compile(
    r"(epoch|unix|timestamp|expiry|expires|expired|expiration|created[_-]?at|"
    r"updated[_-]?at|deleted[_-]?at|last[_-]?seen|event[_-]?time|boot[_-]?time|"
    r"not[_-]?after|valid[_-]?until)",
    re.IGNORECASE,
)

# Duration/counter-like names are usually not Unix epoch timestamps.
# They may still matter in some systems, but they should not dominate a Y2038 review queue.
DURATION_WORD_RE = re.compile(
    r"(timeout|duration|delay|interval|sleep|ttl|elapsed|counter|count|"
    r"(?:^|_)(?:ms|msec|millis|milliseconds|secs|seconds)(?:_|$)|time[_-]?ms)",
    re.IGNORECASE,
)

C_LIKE_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}
SQL_EXTS = {".sql"}
PROTO_EXTS = {".proto"}
MSG_IDL_EXTS = {".msg", ".idl"}
JSON_YAML_EXTS = {".json", ".yaml", ".yml"}
BUILD_NAMES = {"makefile", "cmakelists.txt", "dockerfile", "configure.ac", "configure.in", "meson.build"}
BUILD_EXTS = {".mk", ".cmake", ".toml"}


def iter_files(root: Path, max_file_size: int = 2_000_000) -> Iterable[Path]:
    if root.is_file():
        if is_scannable(root, max_file_size):
            yield root
        return

    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part.lower() in DEFAULT_EXCLUDE_DIRS for part in path.parts):
            continue
        if is_scannable(path, max_file_size):
            yield path


def is_scannable(path: Path, max_file_size: int) -> bool:
    name = path.name.lower()
    if path.suffix.lower() not in TEXT_EXTENSIONS and name not in SPECIAL_NAMES:
        return False
    try:
        return path.stat().st_size <= max_file_size
    except OSError:
        return False


def read_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def scan_path(root: Path, repo_name: Optional[str] = None, max_findings: Optional[int] = None) -> List[Finding]:
    findings: List[Finding] = []
    root = root.resolve()
    for file_path in iter_files(root):
        lines = read_lines(file_path)
        try:
            rel_path = str(file_path.resolve().relative_to(root)) if root.is_dir() else file_path.name
        except ValueError:
            rel_path = str(file_path)
        findings.extend(scan_file(rel_path, lines, file_path.name.lower(), file_path.suffix.lower()))
        if max_findings and len(findings) >= max_findings:
            return findings[:max_findings]
    return findings


def add_finding(
    findings: List[Finding],
    *,
    rule_id: str,
    severity: str,
    confidence: float,
    category: str,
    path: str,
    line: int,
    evidence: str,
    message: str,
    rationale: str,
    suggested_fix: str,
    test_idea: str,
) -> None:
    evidence = evidence.strip()
    if len(evidence) > 220:
        evidence = evidence[:217] + "..."
    findings.append(
        Finding(
            rule_id=rule_id,
            severity=severity,
            confidence=round(confidence, 2),
            category=category,
            path=path,
            line=line,
            evidence=evidence,
            message=message,
            rationale=rationale,
            suggested_fix=suggested_fix,
            test_idea=test_idea,
        )
    )


def scan_file(path: str, lines: List[str], name_lower: str, suffix: str) -> List[Finding]:
    findings: List[Finding] = []
    if suffix in C_LIKE_EXTS:
        scan_c_like(path, lines, findings)
    if suffix in SQL_EXTS:
        scan_sql(path, lines, findings)
    if suffix in PROTO_EXTS:
        scan_proto(path, lines, findings)
    if suffix in MSG_IDL_EXTS:
        scan_msg_idl(path, lines, findings)
    if suffix in JSON_YAML_EXTS:
        scan_json_yaml(path, lines, findings)
    if suffix in BUILD_EXTS or name_lower in BUILD_NAMES:
        scan_build_config(path, lines, findings)
    return findings


def is_probably_absolute_time(name: str) -> bool:
    name = name.lower()
    if DURATION_WORD_RE.search(name) and not ABSOLUTE_TIME_HINT_RE.search(name):
        return False
    return bool(TIME_WORD_RE.search(name) or ABSOLUTE_TIME_HINT_RE.search(name))


def severity_for_width(type_name: str, var_name: str) -> tuple[str, float]:
    t = type_name.replace(" ", "").lower()
    n = var_name.lower()
    if DURATION_WORD_RE.search(n) and not ABSOLUTE_TIME_HINT_RE.search(n):
        return "LOW", 0.35
    if t in {"int32_t", "int", "signedint", "time32_t", "sint32", "sfixed32"}:
        return "HIGH", 0.85
    if t in {"uint32_t", "unsignedint", "uint32", "fixed32"}:
        # unsigned 32-bit epoch can reach 2106, but signed/interop/database assumptions still need review.
        return "MEDIUM", 0.65
    if t == "long":
        # long is 32-bit on Windows and some 32-bit ABIs, 64-bit on many Unix-like 64-bit ABIs.
        return "MEDIUM", 0.55
    return "MEDIUM", 0.5


def scan_c_like(path: str, lines: List[str], findings: List[Finding]) -> None:
    decl_re = re.compile(
        r"\b(?P<type>int32_t|uint32_t|time32_t|unsigned\s+int|signed\s+int|int|long)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
        re.IGNORECASE,
    )
    time_assign_re = re.compile(
        r"\b(?P<type>int32_t|uint32_t|unsigned\s+int|signed\s+int|int|long)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(?\s*(?P=type)\s*\)?\s*)?(?:time|mktime)\s*\(",
        re.IGNORECASE,
    )
    cast_re = re.compile(r"\((?P<type>int32_t|uint32_t|int|long|unsigned\s+int|signed\s+int)\)\s*(?P<expr>[^;]*\b(?:time|mktime|gettimeofday)\b)", re.IGNORECASE)
    sizeof_time_t_re = re.compile(r"\b(?:fread|fwrite|read|write|memcpy|memmove)\b.*sizeof\s*\(\s*time_t\s*\)", re.IGNORECASE)
    raw_time_t_re = re.compile(r"\btime_t\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for match in decl_re.finditer(line):
            type_name = match.group("type")
            var_name = match.group("name")
            if not is_probably_absolute_time(var_name):
                continue
            severity, confidence = severity_for_width(type_name, var_name)
            after_name = line[match.end():].lstrip()
            subject = "function return/name" if after_name.startswith("(") else "field/variable"
            add_finding(
                findings,
                rule_id="C-LIKE-32BIT-TIME-NAMED-FIELD",
                severity=severity,
                confidence=confidence,
                category="source-code timestamp width",
                path=path,
                line=idx,
                evidence=stripped,
                message=f"Possible 32-bit timestamp-like {subject} `{var_name}` declared as `{type_name}`.",
                rationale="A timestamp-like value stored in a 32-bit or ABI-dependent integer can overflow, truncate, or interoperate badly around post-2038 dates.",
                suggested_fix="Confirm whether this stores Unix epoch seconds. If yes, migrate persisted/API-facing values to int64_t or a native time type with a compatibility plan.",
                test_idea="Create/save/read/sort values for 2038-01-19 03:14:07 UTC, 2038-01-19 03:14:08 UTC, and 2040-01-01 UTC.",
            )

        for match in time_assign_re.finditer(line):
            type_name = match.group("type")
            var_name = match.group("name")
            severity, confidence = severity_for_width(type_name, var_name)
            add_finding(
                findings,
                rule_id="C-LIKE-TIME-TO-32BIT-ASSIGNMENT",
                severity="HIGH" if severity != "LOW" else severity,
                confidence=max(confidence, 0.82),
                category="source-code narrowing conversion",
                path=path,
                line=idx,
                evidence=stripped,
                message=f"Potential narrowing assignment from time()/mktime() into `{type_name}` variable `{var_name}`.",
                rationale="time() and mktime() return time_t. Assigning into a 32-bit or ABI-dependent integer can truncate future timestamps.",
                suggested_fix="Keep the value as time_t/int64_t at boundaries; avoid casts or assignments to int/long unless the range is explicitly validated.",
                test_idea="Unit-test this assignment with a fake time provider returning 2040-01-01 UTC and assert no truncation or negative value.",
            )

        for match in cast_re.finditer(line):
            type_name = match.group("type")
            add_finding(
                findings,
                rule_id="C-LIKE-EXPLICIT-TIME-CAST",
                severity="HIGH",
                confidence=0.88,
                category="source-code narrowing conversion",
                path=path,
                line=idx,
                evidence=stripped,
                message=f"Explicit cast of a time-related expression to `{type_name}`.",
                rationale="Explicit casts can hide timestamp truncation and make future-date failures harder to see in review.",
                suggested_fix="Remove the cast where possible, or cast to int64_t with a documented compatibility boundary and tests.",
                test_idea="Add a regression test for 2040-01-01 UTC and assert the casted value remains positive and round-trips correctly.",
            )

        if sizeof_time_t_re.search(line):
            add_finding(
                findings,
                rule_id="C-LIKE-SERIALIZED-TIME-T-SIZEOF",
                severity="MEDIUM",
                confidence=0.75,
                category="binary format / ABI compatibility",
                path=path,
                line=idx,
                evidence=stripped,
                message="Possible serialization/deserialization using sizeof(time_t).",
                rationale="If time_t changes from 32-bit to 64-bit, binary files, persistence formats, or network payloads may become incompatible.",
                suggested_fix="Use an explicit on-disk/on-wire width such as int64_t, add a format version, and maintain migration readers for old data.",
                test_idea="Write data with a simulated 32-bit build and read it with a 64-bit-time build; repeat with post-2038 timestamps.",
            )

        if raw_time_t_re.search(line) and "sizeof" not in line and "typedef" not in line:
            name = raw_time_t_re.search(line).group("name")
            if is_probably_absolute_time(name):
                add_finding(
                    findings,
                    rule_id="C-LIKE-TIME-T-CONTEXT-CHECK",
                    severity="LOW",
                    confidence=0.4,
                    category="platform context needed",
                    path=path,
                    line=idx,
                    evidence=stripped,
                    message=f"`time_t` value `{name}` found; platform/build context decides Y2038 safety.",
                    rationale="time_t is safe on many modern platforms, but can be 32-bit on legacy 32-bit environments unless built with time64 support.",
                    suggested_fix="Check target architectures, libc/kernel support, and whether builds define _TIME_BITS=64 where needed.",
                    test_idea="In CI or an emulator, run sizeof(time_t) and a post-2038 round-trip test on each supported target image.",
                )


def scan_sql(path: str, lines: List[str], findings: List[Finding]) -> None:
    col_re = re.compile(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b\s+"
        r"(?P<type>INT4|INTEGER|INT)(?:\b|\()",
        re.IGNORECASE,
    )
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip().rstrip(",")
        for match in col_re.finditer(line):
            name = match.group("name")
            type_name = match.group("type")
            if not is_probably_absolute_time(name):
                continue
            severity = "HIGH" if re.search(r"epoch|expires|expiry|timestamp|event_time|unix", name, re.I) else "MEDIUM"
            add_finding(
                findings,
                rule_id="SQL-INT-TIMESTAMP-COLUMN",
                severity=severity,
                confidence=0.8 if severity == "HIGH" else 0.62,
                category="database schema timestamp width",
                path=path,
                line=idx,
                evidence=stripped,
                message=f"Timestamp-like SQL column `{name}` uses `{type_name}`.",
                rationale="SQL INT/INTEGER is commonly 32-bit. Unix epoch seconds stored here may overflow or reject post-2038 values.",
                suggested_fix="Migrate to BIGINT for epoch seconds, or preferably a database-native timestamp type if timezone/semantics are clear.",
                test_idea="Insert 2040-01-01 UTC, query it back, verify ordering, expiry logic, indexes, and API serialization.",
            )


def scan_proto(path: str, lines: List[str], findings: List[Finding]) -> None:
    proto_re = re.compile(
        r"\b(?P<type>int32|uint32|sint32|fixed32|sfixed32)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=",
        re.IGNORECASE,
    )
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        for match in proto_re.finditer(line):
            type_name = match.group("type")
            field_name = match.group("name")
            if not is_probably_absolute_time(field_name):
                continue
            severity, confidence = severity_for_width(type_name, field_name)
            add_finding(
                findings,
                rule_id="PROTO-32BIT-TIME-FIELD",
                severity=severity,
                confidence=confidence,
                category="protocol / wire format timestamp width",
                path=path,
                line=idx,
                evidence=stripped,
                message=f"Protobuf field `{field_name}` uses `{type_name}` for timestamp-like data.",
                rationale="Wire-format timestamp widths are harder to change because old and new clients must interoperate.",
                suggested_fix="Add a v2 int64 timestamp field, keep the old field during migration, and define signed/unsigned semantics clearly.",
                test_idea="Test old↔new client exchange with 2038-01-19, 2040-01-01, and for uint32/fixed32 also 2106-02-07 boundary values.",
            )


def scan_msg_idl(path: str, lines: List[str], findings: List[Finding]) -> None:
    msg_re = re.compile(
        r"^\s*(?P<type>int32|uint32|long|unsigned\s+long)\s+"
        r"(?P<name>sec|seconds|stamp|timestamp|[A-Za-z_][A-Za-z0-9_]*(?:time|epoch|expiry|expires|date)[A-Za-z0-9_]*)\b",
        re.IGNORECASE,
    )
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        match = msg_re.search(line)
        if match:
            type_name = match.group("type")
            field_name = match.group("name")
            severity, confidence = severity_for_width(type_name, field_name)
            if field_name.lower() in {"sec", "seconds"} and "time" in path.lower():
                severity, confidence = "HIGH", 0.9
            add_finding(
                findings,
                rule_id="MSG-IDL-32BIT-TIME-FIELD",
                severity=severity,
                confidence=confidence,
                category="message/interface timestamp width",
                path=path,
                line=idx,
                evidence=stripped,
                message=f"Message/interface field `{field_name}` uses `{type_name}` for seconds/time-like data.",
                rationale="Message definitions become public contracts; changing timestamp width can affect serialization, bag files, ABI, and downstream consumers.",
                suggested_fix="Consider a versioned message/interface with int64 seconds or clearly documented conversion rules.",
                test_idea="Run publisher/subscriber or serializer/deserializer tests with dates immediately before and after 2038 rollover.",
            )


def scan_json_yaml(path: str, lines: List[str], findings: List[Finding]) -> None:
    seen_windows: set[int] = set()
    joined_lower = "\n".join(lines).lower()

    # Device/firmware lifecycle context: useful for embedded lifecycle review.
    if re.search(r"architecture\s*[\"':=]+\s*[\"']?(armv7|armhf|i386|x86|mips|powerpc)", joined_lower) and re.search(r"20(3[8-9]|[4-9][0-9])", joined_lower):
        line_no = next((i for i, line in enumerate(lines, start=1) if re.search(r"architecture|lifecycle|support|eol|end", line, re.I)), 1)
        add_finding(
            findings,
            rule_id="MANIFEST-32BIT-LONG-LIVED-DEVICE",
            severity="HIGH",
            confidence=0.78,
            category="device lifecycle context",
            path=path,
            line=line_no,
            evidence=lines[line_no - 1].strip() if lines else "32-bit architecture + post-2038 lifecycle context",
            message="Manifest suggests a 32-bit/legacy architecture with expected life beyond 2038.",
            rationale="Long-lived embedded devices are where Y2038 risk becomes operational: firmware, libc, APIs, and storage may need coordinated validation.",
            suggested_fix="Inventory target OS/libc versions, sizeof(time_t), OTA update path, persisted timestamp formats, and vendor support status.",
            test_idea="Run the device firmware or emulator with system date set to 2040-01-01 and exercise telemetry, TLS, logging, scheduling, and update checks.",
        )

    for idx, _line in enumerate(lines, start=1):
        start = max(0, idx - 4)
        end = min(len(lines), idx + 4)
        window = "\n".join(lines[start:end])
        if not TIME_WORD_RE.search(window):
            continue
        if not re.search(r"\b(int32|uint32|fixed32|integer|int)\b", window, re.I):
            continue
        bucket = idx // 6
        if bucket in seen_windows:
            continue
        seen_windows.add(bucket)
        confidence = 0.62 if re.search(r"int32|fixed32|uint32", window, re.I) else 0.48
        add_finding(
            findings,
            rule_id="JSON-YAML-32BIT-TIME-SCHEMA",
            severity="MEDIUM" if confidence >= 0.6 else "LOW",
            confidence=confidence,
            category="API/schema timestamp width",
            path=path,
            line=idx,
            evidence=" | ".join(s.strip() for s in window.splitlines() if s.strip())[:220],
            message="JSON/YAML schema context suggests timestamp-like data with 32-bit/integer representation.",
            rationale="API schemas often outlive implementations; a 32-bit timestamp field may become a compatibility constraint even if today’s implementation is safe.",
            suggested_fix="Confirm field semantics, document signed/unsigned range, and introduce an int64/string timestamp v2 field if it carries epoch seconds.",
            test_idea="Generate API contract tests for timestamps around 2038-01-19 and verify old/new clients handle responses correctly.",
        )


def scan_build_config(path: str, lines: List[str], findings: List[Finding]) -> None:
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        lower = stripped.lower()
        if "_time_bits=64" in lower:
            add_finding(
                findings,
                rule_id="BUILD-TIME64-FLAG-PRESENT",
                severity="INFO",
                confidence=0.9,
                category="positive control / build configuration",
                path=path,
                line=idx,
                evidence=stripped,
                message="Build config appears to enable 64-bit time support.",
                rationale="This is positive evidence, not a vulnerability. It may reduce Y2038 exposure on supported 32-bit glibc/Linux targets.",
                suggested_fix="Keep this as a documented control and verify target libc/kernel/toolchain support.",
                test_idea="Add a CI check that prints sizeof(time_t) for each target build and runs a 2040 timestamp smoke test.",
            )
        if "_file_offset_bits=64" in lower:
            add_finding(
                findings,
                rule_id="BUILD-FILE-OFFSET64-FLAG-PRESENT",
                severity="INFO",
                confidence=0.75,
                category="supporting build configuration",
                path=path,
                line=idx,
                evidence=stripped,
                message="Build config enables 64-bit file offsets; often paired with 64-bit time migrations.",
                rationale="Some platforms require file-offset and time-width feature macros together for compatibility.",
                suggested_fix="Verify whether _TIME_BITS=64 is also required for the target platform.",
                test_idea="Compile a tiny target-specific smoke test that prints sizeof(time_t), sizeof(off_t), and handles 2040-01-01.",
            )
        if re.search(r"\b(-m32|i386|x86_32|armhf|armv7|mips32)\b", lower):
            add_finding(
                findings,
                rule_id="BUILD-32BIT-TARGET-CONTEXT",
                severity="MEDIUM",
                confidence=0.65,
                category="platform context",
                path=path,
                line=idx,
                evidence=stripped,
                message="Build config references a 32-bit architecture/target.",
                rationale="32-bit target context does not prove Y2038 risk, but it increases the need to validate time_t width and timestamp storage.",
                suggested_fix="Record target OS/libc/kernel/toolchain versions and run time-width smoke tests in CI for this target.",
                test_idea="Build the 32-bit target and execute a post-2038 timestamp round-trip test under emulator or hardware-in-the-loop.",
            )
