# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Data-store integrity: SQLite schema, constraint, and money-type auditing.

Two entry points share one finding vocabulary: :func:`audit_ddl` parses
``CREATE TABLE`` statements (works in CI with no database file), and
:func:`audit_sqlite` inspects a real SQLite database through ``PRAGMA``
queries. No ORM and no migration tool are required.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text

__all__ = [
    "DbReport",
    "TableFacts",
    "audit_ddl",
    "audit_sqlite",
    "parse_ddl_tables",
]

_CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`\[]?(?P<name>\w+)[\"`\]]?\s*\((?P<body>.*?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_MONEY_RE = re.compile(
    r"(?i)(?:^|_)(price|amount|total|cost|balance|fee|salary|subtotal|tax|discount|revenue)(?:_|$)"
)
_DATE_RE = re.compile(r"(?i)\b(created|updated|deleted|expires?|timestamp|date|time)_?(at)?\b")
_ID_RE = re.compile(r"(?i)^(id|[a-z_]+_id)$")
_RESERVED = frozenset(
    {
        "order",
        "group",
        "select",
        "from",
        "where",
        "table",
        "index",
        "user",
        "primary",
        "key",
        "default",
        "values",
        "check",
        "limit",
        "join",
    }
)


def _finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=redact_text(evidence),
        recommendation=recommendation,
    )


@dataclass
class TableFacts:
    name: str
    columns: tuple[str, ...] = ()
    primary_key: tuple[str, ...] = ()
    foreign_keys: tuple[tuple[str, str, str], ...] = ()
    not_null: tuple[str, ...] = ()
    money_columns: tuple[str, ...] = ()
    float_columns: tuple[str, ...] = ()
    unique_columns: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "columns": list(self.columns),
            "primary_key": list(self.primary_key),
            "foreign_keys": [list(item) for item in self.foreign_keys],
            "not_null": list(self.not_null),
            "money_columns": list(self.money_columns),
            "float_columns": list(self.float_columns),
            "unique_columns": list(self.unique_columns),
        }


@dataclass
class DbReport:
    target: str = ""
    engine: str = "sqlite"
    schema_version: int = 0
    tables: list[TableFacts] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": redact_text(self.target),
            "engine": self.engine,
            "schema_version": self.schema_version,
            "tables": [table.to_dict() for table in self.tables],
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _split_columns(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in body:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _column_name(definition: str) -> str:
    token = definition.strip().split()[0] if definition.strip() else ""
    return token.strip('"`[]')


def parse_ddl_tables(ddl: str) -> list[TableFacts]:
    """Parse ``CREATE TABLE`` statements into table facts."""
    tables: list[TableFacts] = []
    for match in _CREATE_RE.finditer(ddl or ""):
        name = match.group("name")
        body = match.group("body")
        facts = TableFacts(name=name)
        primary_key: list[str] = []
        foreign_keys: list[tuple[str, str, str]] = []
        not_null: list[str] = []
        columns: list[str] = []
        money: list[str] = []
        floats: list[str] = []
        unique: list[str] = []
        for definition in _split_columns(body):
            upper = definition.upper()
            if upper.startswith(("PRIMARY KEY", "FOREIGN KEY", "UNIQUE", "CHECK", "CONSTRAINT")):
                if upper.startswith("PRIMARY KEY"):
                    primary_key.extend(re.findall(r"[\"`\[]?(\w+)[\"`\]]?", definition.split("(", 1)[-1]))
                fk = re.search(
                    r"FOREIGN\s+KEY\s*\(\s*[\"`\[]?(\w+)[\"`\]]?\s*\)\s*REFERENCES\s+[\"`\[]?(\w+)[\"`\]]?\s*\(\s*[\"`\[]?(\w+)[\"`\]]?",
                    definition,
                    re.IGNORECASE,
                )
                if fk:
                    foreign_keys.append((fk.group(1), fk.group(2), fk.group(3)))
                continue
            column = _column_name(definition)
            if not column:
                continue
            columns.append(column)
            if "PRIMARY KEY" in upper:
                primary_key.append(column)
            if "NOT NULL" in upper:
                not_null.append(column)
            if "UNIQUE" in upper:
                unique.append(column)
            if "REFERENCES" in upper:
                fk = re.search(
                    r"REFERENCES\s+[\"`\[]?(\w+)[\"`\]]?\s*\(\s*[\"`\[]?(\w+)[\"`\]]?",
                    definition,
                    re.IGNORECASE,
                )
                if fk:
                    foreign_keys.append((column, fk.group(1), fk.group(2)))
            if _MONEY_RE.search(column):
                money.append(column)
                if re.search(r"(?i)\b(REAL|FLOAT|DOUBLE|NUMERIC|DECIMAL)\b", upper):
                    floats.append(column)
        facts.columns = tuple(columns)
        facts.primary_key = tuple(primary_key)
        facts.foreign_keys = tuple(foreign_keys)
        facts.not_null = tuple(not_null)
        facts.money_columns = tuple(money)
        facts.float_columns = tuple(floats)
        facts.unique_columns = tuple(unique)
        tables.append(facts)
    return tables


def _shared_findings(report: DbReport, *, foreign_key_indexes: Iterable[tuple[str, str]] = ()) -> None:
    indexed = {tuple(item) for item in foreign_key_indexes}
    if not report.tables:
        report.findings.append(
            _finding(
                "No tables found",
                Severity.HIGH,
                "db-empty-schema",
                "The schema declares no tables, so no internality could be verified.",
                "tables=0",
                "Point the audit at the schema or database that backs the product.",
            )
        )
    for table in report.tables:
        if not table.primary_key:
            report.findings.append(
                _finding(
                    "Table has no primary key",
                    Severity.HIGH,
                    "db-primary-key",
                    f"'{table.name}' cannot uniquely identify a row.",
                    f"table={table.name}",
                    "Add an integer/UUID primary key so updates and deletes are deterministic.",
                )
            )
            for column in table.columns:
                if _ID_RE.match(column) and column != "id":
                    report.findings.append(
                        _finding(
                            "Reference column without a primary key",
                            Severity.MEDIUM,
                            "db-primary-key",
                            f"'{table.name}.{column}' looks like a reference but the table has no key.",
                            f"{table.name}.{column}",
                            "Declare the primary key before adding foreign references.",
                        )
                    )
        for column in table.float_columns:
            report.findings.append(
                _finding(
                    "Money stored as an approximate type",
                    Severity.HIGH,
                    "db-money-float",
                    f"'{table.name}.{column}' uses a float type, which loses cents.",
                    f"{table.name}.{column}",
                    "Store integer cents or a fixed-precision NUMERIC/DECIMAL value.",
                )
            )
        for column, target, target_column in table.foreign_keys:
            if (table.name, column) not in indexed:
                report.findings.append(
                    _finding(
                        "Foreign key without an index",
                        Severity.MEDIUM,
                        "db-fk-index",
                        f"'{table.name}.{column}' references '{target}.{target_column}' with no index.",
                        f"{table.name}.{column} -> {target}.{target_column}",
                        "Index every foreign key used by joins or cascades.",
                    )
                )
        for column in table.columns:
            if _DATE_RE.search(column) and column not in table.not_null:
                report.findings.append(
                    _finding(
                        "Temporal column is nullable",
                        Severity.LOW,
                        "db-nullable-timestamp",
                        f"'{table.name}.{column}' can be null, which breaks range queries.",
                        f"{table.name}.{column}",
                        "Add NOT NULL with a default, or document the null meaning.",
                    )
                )
            if column.lower() in _RESERVED:
                report.findings.append(
                    _finding(
                        "Reserved SQL keyword used as a column name",
                        Severity.LOW,
                        "db-reserved-word",
                        f"'{table.name}.{column}' needs quoting in every query.",
                        f"{table.name}.{column}",
                        "Rename the column to avoid quoting bugs across engines.",
                    )
                )
        if not table.not_null and table.columns:
            report.findings.append(
                _finding(
                    "Table has no NOT NULL constraints",
                    Severity.LOW,
                    "db-null-constraints",
                    f"'{table.name}' accepts null in every column.",
                    f"table={table.name}",
                    "Mark required fields NOT NULL so bad writes fail early.",
                )
            )
    if report.tables and report.schema_version <= 0:
        report.findings.append(
            _finding(
                "Schema version is not tracked",
                Severity.MEDIUM,
                "db-schema-version",
                "PRAGMA user_version is 0, so migrations cannot be ordered safely.",
                "user_version=0",
                "Set user_version (or a migrations table) and assert it in CI.",
            )
        )
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )


def audit_ddl(ddl: str, *, target: str = "schema.sql", schema_version: int = 0) -> DbReport:
    """Audit a SQL schema without opening a database."""
    report = DbReport(target=target, schema_version=schema_version, tables=parse_ddl_tables(ddl))
    _shared_findings(report)
    return report


def audit_sqlite(path: str | Path, *, sample_rows: int = 3) -> DbReport:
    """Audit a SQLite database file through PRAGMA introspection."""
    target = Path(path)
    report = DbReport(target=str(target))
    if not target.is_file():
        report.findings.append(
            _finding(
                "Database file not found",
                Severity.HIGH,
                "db-missing",
                "The SQLite file does not exist, so no integrity checks ran.",
                str(target),
                "Create the database or fix the path.",
            )
        )
        return report
    try:
        connection = sqlite3.connect(f"file:{target.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        report.findings.append(
            _finding(
                "Database could not be opened",
                Severity.HIGH,
                "db-open",
                "SQLite rejected the file.",
                f"{type(exc).__name__}: {exc}",
                "Verify the database is a valid SQLite file and readable.",
            )
        )
        return report

    fk_indexes: list[tuple[str, str]] = []
    try:
        report.schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0] or 0)
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        indexes = list(
            connection.execute(
                "SELECT tbl_name, name, sql FROM sqlite_master WHERE type='index' AND tbl_name NOT LIKE 'sqlite_%'"
            )
        )
        for name in names:
            quoted = '"' + str(name).replace('"', '""') + '"'
            columns_info = list(connection.execute(f"PRAGMA table_info({quoted})"))
            columns = tuple(str(row[1]) for row in columns_info)
            primary_key = tuple(str(row[1]) for row in columns_info if row[5])
            not_null = tuple(str(row[1]) for row in columns_info if row[3] and not row[5])
            declared = {str(row[1]): str(row[2] or "").upper() for row in columns_info}
            unique = tuple(
                str(index_row[1])
                for index_row in connection.execute(f"PRAGMA index_list({quoted})")
                if int(index_row[2]) == 1
            )
            foreign_keys = tuple(
                (str(row[3]), str(row[2]), str(row[4]))
                for row in connection.execute(f"PRAGMA foreign_key_list({quoted})")
            )
            for index_name, index_sql in ((row[1], row[2]) for row in indexes if row[0] == name):
                if not index_sql:
                    continue
                match = re.search(r"\(([^)]*)\)", index_sql)
                if not match:
                    continue
                for column in re.split(r"\s*,\s*", match.group(1)):
                    fk_indexes.append((str(name), column.strip().strip('"`[]')))
            money = tuple(column for column in columns if _MONEY_RE.search(column))
            floats = tuple(
                column
                for column in money
                if any(token in declared.get(column, "") for token in ("REAL", "FLOAT", "DOUBLE"))
            )
            report.tables.append(
                TableFacts(
                    name=str(name),
                    columns=columns,
                    primary_key=primary_key,
                    foreign_keys=foreign_keys,
                    not_null=not_null,
                    money_columns=money,
                    float_columns=floats,
                    unique_columns=unique,
                )
            )
            for column in money:
                try:
                    sample = list(
                        connection.execute(
                            f'SELECT {sample_rows} "{column}" FROM "{name}" WHERE "{column}" IS NOT NULL LIMIT {sample_rows}'
                        )
                    )
                except sqlite3.Error:
                    continue
                for (value,) in sample:
                    if isinstance(value, float) and round(value, 2) != value:
                        report.findings.append(
                            _finding(
                                "Monetary value has sub-cent precision",
                                Severity.MEDIUM,
                                "db-money-rounding",
                                f"'{name}.{column}' stores a float that will not round-trip.",
                                f"{name}.{column}={value!r}",
                                "Store integer cents so totals reconcile exactly.",
                            )
                        )
                        break
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity and str(integrity[0]).lower() != "ok":
            report.findings.append(
                _finding(
                    "SQLite integrity check failed",
                    Severity.CRITICAL,
                    "db-integrity",
                    "The database file reported corruption.",
                    str(integrity[0]),
                    "Restore from a verified backup before serving traffic.",
                )
            )
        try:
            bad_fk = list(connection.execute("PRAGMA foreign_key_check"))
        except sqlite3.Error as exc:
            report.findings.append(
                _finding(
                    "Foreign key target is not a key",
                    Severity.HIGH,
                    "db-foreign-key-target",
                    "A foreign key references a column that is not unique, so enforcement is broken.",
                    str(exc),
                    "Point the foreign key at the parent primary key or a UNIQUE column.",
                )
            )
        else:
            if bad_fk:
                report.findings.append(
                    _finding(
                        "Foreign key violations present",
                        Severity.HIGH,
                        "db-foreign-key",
                        "Rows point at parents that no longer exist.",
                        f"violations={len(bad_fk)}",
                        "Enable PRAGMA foreign_keys=ON and repair the orphan rows.",
                    )
                )
    except sqlite3.Error as exc:
        report.findings.append(
            _finding(
                "SQLite introspection failed",
                Severity.MEDIUM,
                "db-introspection",
                "Part of the schema could not be read.",
                f"{type(exc).__name__}: {exc}",
                "Check the file is not encrypted or partially written.",
            )
        )
    finally:
        connection.close()

    _shared_findings(report, foreign_key_indexes=fk_indexes)
    return report
