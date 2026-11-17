"""Translate Sigma rules (https://sigmahq.io) into custom detection rules.

The custom-rule engine is an AND of field conditions, each of which may hold
a list of values (OR) and may be negated (NOT), plus a minimum event count
in a time window. That covers the common shape of a Sigma rule:

    selection [and selection2 ...] [and not filter ...] [| count() [by F] > N]

Anything it cannot express faithfully is rejected with a reason rather than
approximated: regular expressions, OR between selections, a negated
selection over more than one field, fields with no CyberShield equivalent,
and Sigma's newer correlation rules. A rule that imports is created as a
DRAFT so an analyst reviews and dry-runs it before it raises alerts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.detection.rules.custom_condition import NUMBER_FIELDS

MAX_RULES_PER_IMPORT = 50
MAX_CONDITIONS = 10
MAX_STORED_SOURCE = 4000

# Sigma field names (Windows/Sysmon, ECS-style and common log fields) onto
# the fields a custom rule can read. Compared case-insensitively.
FIELD_MAP: dict[str, str] = {
    **dict.fromkeys(
        ["sourceip", "src_ip", "source.ip", "ipaddress", "clientip", "client_ip", "c-ip", "src",
         "ip_address", "sourceaddress", "remoteaddress", "client.ip"],
        "ip_address",
    ),
    **dict.fromkeys(
        ["destinationip", "dst_ip", "destination.ip", "destaddress", "dst", "dest_ip",
         "destinationaddress", "server.ip"],
        "dest_ip",
    ),
    **dict.fromkeys(
        ["destinationport", "dst_port", "destination.port", "destport", "dport", "port", "dest_port"],
        "port",
    ),
    **dict.fromkeys(
        ["user", "username", "user.name", "targetusername", "subjectusername", "accountname",
         "samaccountname", "cs-username", "user_name"],
        "username",
    ),
    **dict.fromkeys(
        ["computer", "computername", "hostname", "host.name", "host", "workstation",
         "workstationname", "dvchost"],
        "hostname",
    ),
    **dict.fromkeys(
        ["image", "process", "process.name", "process.executable", "processname", "app", "program",
         "newprocessname"],
        "process",
    ),
    **dict.fromkeys(
        ["commandline", "command", "process.command_line", "cmdline", "processcommandline"],
        "command",
    ),
    **dict.fromkeys(
        ["targetfilename", "file.path", "filename", "file_path", "filepath", "objectname"],
        "file_path",
    ),
    **dict.fromkeys(["queryname", "dns.question.name", "query", "dns_query", "qname"], "dns_query"),
    **dict.fromkeys(
        ["destinationhostname", "destination.domain", "url.domain", "cs-host", "domain",
         "r-dns", "c-uri-host", "dest_domain"],
        "domain",
    ),
    **dict.fromkeys(["protocol", "network.transport", "proto", "transport"], "protocol"),
    **dict.fromkeys(["message", "msg", "keywords", "log.message"], "message"),
    "event_type": "event_type",
    "status": "status",
    "event.outcome": "status",
}

GROUP_BY_FIELDS = {"ip_address", "username"}

LEVELS = {
    "informational": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

TACTICS = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TIMEFRAME = re.compile(r"^(\d+)\s*([smhd])$", re.IGNORECASE)
_TIMEFRAME_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_AGGREGATION = re.compile(
    r"^count\(\s*\)\s*(?:by\s+(?P<by>[\w.\-]+)\s*)?(?P<op>>=|>)\s*(?P<n>\d+)$",
    re.IGNORECASE,
)
_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "gt", "gte", "lt", "lte"}


class SigmaUnsupported(ValueError):
    """The rule uses something the custom-rule engine cannot express."""


@dataclass
class TranslatedRule:
    name: str
    severity: str
    tactic: str | None
    mitre_technique: str | None
    conditions: list[dict]
    group_by: str
    window_seconds: int
    min_count: int
    external_id: str | None
    source_text: str | None
    notes: list[str] = field(default_factory=list)


# --- values -------------------------------------------------------------------


def _scalar(value: Any, where: str) -> str:
    if isinstance(value, bool) or value is None or isinstance(value, (dict, list)):
        raise SigmaUnsupported(f"{where}: only text and number values are supported.")
    return str(value)


def _wildcard_operator(text: str, where: str) -> tuple[str, str]:
    """Plain Sigma values may use * at either end: *x* contains, x* startswith."""

    if "?" in text.replace("\\?", ""):
        raise SigmaUnsupported(f"{where}: the ? wildcard is not supported.")
    body = text
    leading = body.startswith("*")
    trailing = body.endswith("*") and not body.endswith("\\*")
    if leading:
        body = body[1:]
    if trailing and body:
        body = body[:-1]
    if "*" in body.replace("\\*", ""):
        raise SigmaUnsupported(f"{where}: a wildcard inside a value is not supported.")
    body = body.replace("\\*", "*").replace("\\?", "?")
    if not body:
        raise SigmaUnsupported(f"{where}: a value of only wildcards matches everything.")
    if leading and trailing:
        return "contains", body
    if leading:
        return "endswith", body
    if trailing:
        return "startswith", body
    return "equals", body


def _field_conditions(key: str, raw_value: Any, *, negate: bool) -> list[dict]:
    """One Sigma `field|modifiers: value(s)` entry as engine conditions."""

    name, *modifiers = key.split("|")
    target = FIELD_MAP.get(name.strip().lower())
    if target is None:
        raise SigmaUnsupported(f"field '{name}' has no CyberShield equivalent.")
    modifiers = [modifier.strip().lower() for modifier in modifiers if modifier.strip()]
    unsupported = [modifier for modifier in modifiers if modifier not in _SUPPORTED_MODIFIERS]
    if unsupported:
        raise SigmaUnsupported(f"{key}: the '{unsupported[0]}' modifier is not supported.")

    values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not values:
        raise SigmaUnsupported(f"{key}: an empty value list matches nothing.")
    texts = [_scalar(value, key) for value in values]
    match_all = "all" in modifiers
    comparisons = [modifier for modifier in modifiers if modifier in {"gt", "gte", "lt", "lte"}]
    operators = [modifier for modifier in modifiers if modifier in {"contains", "startswith", "endswith"}]
    if len(operators) + len(comparisons) > 1:
        raise SigmaUnsupported(f"{key}: combining comparison modifiers is not supported.")

    if comparisons:
        if target not in NUMBER_FIELDS or len(texts) != 1:
            raise SigmaUnsupported(f"{key}: numeric comparisons apply to a single port value only.")
        if not texts[0].isdigit():
            raise SigmaUnsupported(f"{key}: '{texts[0]}' is not a whole number.")
        number = int(texts[0])
        # The engine has strict > and <; whole-number ports make >= N the same as > N-1.
        operator, bound = {
            "gt": (">", number), "gte": (">", number - 1), "lt": ("<", number), "lte": ("<", number + 1),
        }[comparisons[0]]
        return [_condition(target, operator, [str(bound)], negate)]

    if target in NUMBER_FIELDS:
        if operators or any(not text.isdigit() for text in texts):
            raise SigmaUnsupported(f"{key}: a port condition needs whole-number values.")
        return [_condition(target, "equals", texts, negate)]

    pairs = []
    for text in texts:
        if operators:
            # With an explicit modifier the value is literal, wildcards and all.
            pairs.append((operators[0], text))
        else:
            pairs.append(_wildcard_operator(text, key))

    if match_all:
        if negate and len(pairs) > 1:
            raise SigmaUnsupported(f"{key}: a negated '|all' over several values is not supported.")
        return [_condition(target, operator, [value], negate) for operator, value in pairs]

    by_operator: dict[str, list[str]] = {}
    for operator, value in pairs:
        by_operator.setdefault(operator, []).append(value)
    if len(by_operator) > 1:
        # e.g. [cmd.exe, *\\powershell.exe]: an OR across two operators.
        raise SigmaUnsupported(f"{key}: mixing exact and wildcard values in one list is not supported.")
    (operator, grouped), = by_operator.items()
    return [_condition(target, operator, grouped, negate)]


def _condition(target: str, operator: str, values: list[str], negate: bool) -> dict:
    condition: dict[str, Any] = {"field": target, "operator": operator, "timezone": None}
    if len(values) == 1:
        condition["value"] = values[0]
    else:
        condition["values"] = values
    if negate:
        condition["negate"] = True
    return condition


def _selection_conditions(name: str, selection: Any, *, negate: bool) -> list[dict]:
    if isinstance(selection, list):
        if selection and all(isinstance(item, (str, int)) for item in selection):
            # Keyword list: any of these strings anywhere in the message.
            texts = [_scalar(item, name) for item in selection]
            return [_condition("message", "contains", [text.strip("*") for text in texts], negate)]
        if len(selection) == 1 and isinstance(selection[0], dict):
            selection = selection[0]
        else:
            raise SigmaUnsupported(f"selection '{name}' is a list of alternatives (an OR), which is not supported.")
    if not isinstance(selection, dict) or not selection:
        raise SigmaUnsupported(f"selection '{name}' is empty or malformed.")
    if negate and len(selection) > 1:
        raise SigmaUnsupported(
            f"'not {name}' negates several fields at once, which needs an OR the engine cannot express."
        )
    conditions: list[dict] = []
    for key, value in selection.items():
        conditions.extend(_field_conditions(str(key), value, negate=negate))
    return conditions


# --- the condition expression -------------------------------------------------


def _expand(term: str, selections: dict) -> list[str]:
    """`selection`, `1 of sel*`, `all of sel*`, `all of them` -> selection names."""

    words = term.split()
    if len(words) == 1:
        if words[0] not in selections:
            raise SigmaUnsupported(f"the condition names '{words[0]}', which is not defined.")
        return [words[0]]
    if len(words) == 3 and words[1] == "of" and words[0] in {"1", "all", "any"}:
        pattern = words[2]
        if pattern == "them":
            names = list(selections)
        else:
            prefix = pattern.rstrip("*")
            names = [name for name in selections if (name.startswith(prefix) if pattern.endswith("*") else name == prefix)]
        if not names:
            raise SigmaUnsupported(f"'{term}' matches no selection.")
        if words[0] in {"1", "any"} and len(names) > 1:
            raise SigmaUnsupported(f"'{term}' is an OR across selections, which is not supported.")
        return names
    raise SigmaUnsupported(f"the condition part '{term}' is not supported.")


def _parse_condition(expression: str, selections: dict) -> tuple[list[tuple[str, bool]], str | None]:
    """The expression as [(selection, negated), ...] joined by AND, plus any aggregation."""

    main, _, aggregation = expression.partition("|")
    main = " ".join(main.split())
    if not main:
        raise SigmaUnsupported("the condition is empty.")
    if "(" in main or ")" in main:
        raise SigmaUnsupported("parentheses in the condition are not supported.")
    if re.search(r"\bor\b", main, re.IGNORECASE):
        raise SigmaUnsupported("OR between selections is not supported.")

    parts: list[tuple[str, bool]] = []
    for term in re.split(r"\s+and\s+", main, flags=re.IGNORECASE):
        negate = False
        if term.lower().startswith("not "):
            negate, term = True, term[4:].strip()
        names = _expand(term, selections)
        if negate and len(names) > 1:
            raise SigmaUnsupported(f"'not {term}' negates several selections, which is not supported.")
        parts.extend((name, negate) for name in names)
    if all(negate for _, negate in parts):
        raise SigmaUnsupported("a rule made only of negations would match almost every event.")
    return parts, aggregation.strip() or None


# --- one rule -----------------------------------------------------------------


def _timeframe_seconds(value: Any) -> int:
    match = _TIMEFRAME.match(str(value).strip())
    if not match:
        raise SigmaUnsupported(f"timeframe '{value}' is not in the form 30s, 5m, 1h or 1d.")
    seconds = int(match.group(1)) * _TIMEFRAME_SECONDS[match.group(2).lower()]
    if not 60 <= seconds <= 86400:
        raise SigmaUnsupported(f"timeframe '{value}' is outside the supported 1 minute to 1 day.")
    return seconds


def _attack_tags(tags: Any) -> tuple[str | None, str | None]:
    technique = tactic = None
    for tag in tags if isinstance(tags, list) else []:
        text = str(tag).strip().lower()
        found = _TECHNIQUE_TAG.match(text)
        if found and technique is None:
            technique = found.group(1).upper()
        elif text.startswith("attack.") and tactic is None:
            tactic = TACTICS.get(text.removeprefix("attack.").replace("-", "_"))
    return technique, tactic


def translate_rule(document: Any, source_text: str | None = None) -> TranslatedRule:
    if not isinstance(document, dict):
        raise SigmaUnsupported("the document is not a Sigma rule.")
    if "correlation" in document or document.get("type") == "correlation":
        raise SigmaUnsupported("Sigma correlation rules are not supported; use count() in the condition.")
    title = str(document.get("title") or "").strip()
    if not title:
        raise SigmaUnsupported("the rule has no title.")
    detection = document.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaUnsupported("the rule has no detection condition.")

    condition = detection["condition"]
    if isinstance(condition, list):
        if len(condition) != 1:
            raise SigmaUnsupported("several alternative conditions (an OR) are not supported.")
        condition = condition[0]
    selections = {
        key: value for key, value in detection.items() if key not in {"condition", "timeframe"}
    }
    parts, aggregation = _parse_condition(str(condition), selections)

    conditions: list[dict] = []
    for name, negate in parts:
        conditions.extend(_selection_conditions(name, selections[name], negate=negate))
    if len(conditions) > MAX_CONDITIONS:
        raise SigmaUnsupported(
            f"it needs {len(conditions)} conditions; a custom rule holds at most {MAX_CONDITIONS}."
        )

    notes: list[str] = []
    min_count, group_by = 1, "none"
    timeframe = detection.get("timeframe")
    window = _timeframe_seconds(timeframe) if timeframe is not None else 600
    if aggregation:
        found = _AGGREGATION.match(aggregation)
        if not found:
            raise SigmaUnsupported(f"the aggregation '{aggregation}' is not supported; only count() > N is.")
        threshold = int(found.group("n"))
        min_count = threshold + 1 if found.group("op") == ">" else max(1, threshold)
        if found.group("by"):
            target = FIELD_MAP.get(found.group("by").lower())
            if target not in GROUP_BY_FIELDS:
                raise SigmaUnsupported(
                    f"count() by {found.group('by')} is not supported; group by a source IP or user."
                )
            group_by = target
        if timeframe is None:
            notes.append("No timeframe was given for the count, so a 10-minute window is used.")

    level = str(document.get("level") or "medium").strip().lower()
    if level not in LEVELS:
        notes.append(f"Level '{level}' is not a Sigma level, so the rule is MEDIUM.")
    technique, tactic = _attack_tags(document.get("tags"))
    if document.get("logsource"):
        notes.append("The logsource is not used: the rule runs on every uploaded event.")

    external_id = str(document.get("id") or "").strip()[:100] or None
    return TranslatedRule(
        name=title[:120],
        severity=LEVELS.get(level, "MEDIUM"),
        tactic=tactic,
        mitre_technique=technique,
        conditions=conditions,
        group_by=group_by,
        window_seconds=window,
        min_count=min_count,
        external_id=external_id,
        source_text=source_text if source_text and len(source_text) <= MAX_STORED_SOURCE else None,
        notes=notes,
    )


# --- many rules ---------------------------------------------------------------


def _split_documents(content: str) -> list[str]:
    """The text of each YAML document, so each rule keeps its own source."""

    chunks: list[list[str]] = [[]]
    for line in content.replace("\r\n", "\n").split("\n"):
        if line.rstrip() == "---":
            chunks.append([])
        else:
            chunks[-1].append(line)
    return ["\n".join(chunk).strip() for chunk in chunks if "\n".join(chunk).strip()]


def parse_sigma(content: str) -> list[tuple[str, Any, str | None, str]]:
    """[(label, parsed document or None, YAML error or None, source text), ...]."""

    documents = _split_documents(content)
    if len(documents) > MAX_RULES_PER_IMPORT:
        raise SigmaUnsupported(f"An import holds at most {MAX_RULES_PER_IMPORT} rules.")
    parsed = []
    for index, text in enumerate(documents, start=1):
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" (line {mark.line + 1})" if mark is not None else ""
            parsed.append((f"Rule {index}", None, f"The YAML could not be read{where}.", text))
            continue
        label = str(document.get("title")).strip() if isinstance(document, dict) and document.get("title") else f"Rule {index}"
        parsed.append((label[:120], document, None, text))
    return parsed
