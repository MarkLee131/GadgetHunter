"""Model of a target application's deserialization class filter (allow/deny).

Supports two sources, auto-extracted or supplied explicitly:
  * a JEP 290 ObjectInputFilter pattern string (jdk.serialFilter style), and
  * an application class whitelist (e.g. JasperReports' DeserializationClassFilter),
    whose wildcard semantics this module reproduces exactly: a single '*' matches
    within one package segment ([^.]*), '**' matches across segments (.*), and a
    pattern with no wildcard is an exact class name; unmatched classes are denied.

`decide(class_name)` returns "allow", "deny", or "unknown"; the caller treats
"deny" as a feasibility blocker and "unknown" as undecided (no constraint).
"""

import logging
import re
from typing import List, Optional

logger = logging.getLogger(__name__)


def _wildcard_to_regex(pattern: str) -> "re.Pattern":
    """Mirror StandardClassWhitelist.addPattern: '*'→[^.]*, '**'→.*, rest quoted."""
    out = []
    i = 0
    for m in re.finditer(r"\*+", pattern):
        if m.start() > i:
            out.append(re.escape(pattern[i:m.start()]))
        out.append("[^.]*" if (m.end() - m.start()) == 1 else ".*")
        i = m.end()
    if i < len(pattern):
        out.append(re.escape(pattern[i:]))
    return re.compile("".join(out))


class DeserializationFilter:
    """Allow/deny decision for deserialized class names.

    whitelist mode: a class is allowed iff it matches an allow rule; otherwise
    denied. jep290 mode: rules are tried in order; the first matching rule
    (deny rules carry a '!' prefix) decides; no match is "unknown".
    """

    def __init__(self, allow_exact=None, allow_patterns=None, deny_patterns=None,
                 mode: str = "whitelist", name: str = ""):
        self.allow_exact = set(allow_exact or [])
        self.allow_patterns = [_wildcard_to_regex(p) for p in (allow_patterns or [])]
        self.deny_patterns = [_wildcard_to_regex(p) for p in (deny_patterns or [])]
        self.mode = mode
        self.name = name

    @property
    def empty(self) -> bool:
        return not (self.allow_exact or self.allow_patterns or self.deny_patterns)

    def decide(self, class_name: str) -> str:
        class_name = (class_name or "").strip()
        # arrays: decide on the element type (mirrors resolveClass handling)
        while class_name.startswith("["):
            class_name = class_name[1:]
            if class_name.startswith("L") and class_name.endswith(";"):
                class_name = class_name[1:-1]
        if not class_name:
            return "unknown"
        if any(p.fullmatch(class_name) for p in self.deny_patterns):
            return "deny"
        if class_name in self.allow_exact or any(p.fullmatch(class_name) for p in self.allow_patterns):
            return "allow"
        # whitelist: unmatched is denied; jep290: unmatched is undecided
        return "deny" if self.mode == "whitelist" else "unknown"

    def allows(self, class_name: str) -> bool:
        return self.decide(class_name) == "allow"


_WHITELIST_PROP_PREFIX = "net.sf.jasperreports.deserialization.class.whitelist."
# Hardcoded base whitelist from DeserializationClassFilter.addExtraWhitelists.
_JR_HARDCODED = [
    "java.lang.Boolean", "java.lang.Byte", "java.lang.Character", "java.lang.Double",
    "java.lang.Enum", "java.lang.Float", "java.lang.Integer", "java.lang.Long",
    "java.lang.Number", "java.lang.Object", "java.lang.Short", "java.lang.String",
]


def from_jasperreports(properties_text: str) -> Optional["DeserializationFilter"]:
    """Build a whitelist filter from jasperreports *.properties content
    (the deserialization.class.whitelist.* entries), plus the hardcoded base."""
    exact, patterns = set(_JR_HARDCODED), []
    # properties use line-continuations (\ at EOL); join them first.
    joined = re.sub(r"\\\s*\n\s*", "", properties_text)
    found = False
    for line in joined.splitlines():
        line = line.strip()
        if not line.startswith(_WHITELIST_PROP_PREFIX) or "=" not in line:
            continue
        found = True
        value = line.split("=", 1)[1]
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "*" in entry:
                patterns.append(entry)
            else:
                exact.add(entry)
    if not found:
        return None
    return DeserializationFilter(allow_exact=exact, allow_patterns=patterns,
                                 mode="whitelist", name="jasperreports")


def from_jep290(spec: str) -> "DeserializationFilter":
    """Parse a JEP 290 jdk.serialFilter pattern string (allow/deny, '!'=deny,
    '*'/'**' wildcards). Limit directives (maxdepth=, maxbytes=, module '/') are
    ignored for class decisions."""
    allow_exact, allow_patterns, deny_patterns = set(), [], []
    for raw in spec.split(";"):
        raw = raw.strip()
        if not raw or "=" in raw:  # skip limit directives like maxdepth=10
            continue
        deny = raw.startswith("!")
        pat = raw[1:] if deny else raw
        if "/" in pat:  # drop module prefix
            pat = pat.split("/", 1)[1]
        if deny:
            deny_patterns.append(pat)
        elif "*" in pat:
            allow_patterns.append(pat)
        else:
            allow_exact.add(pat)
    return DeserializationFilter(allow_exact=allow_exact, allow_patterns=allow_patterns,
                                 deny_patterns=deny_patterns, mode="jep290", name="jep290")


def from_classpath(classpath) -> Optional["DeserializationFilter"]:
    """Best-effort auto-extraction: scan classpath JARs for a .properties entry
    that declares a deserialization class whitelist (JasperReports style)."""
    import os
    import zipfile
    if isinstance(classpath, str):
        sep = ";" if os.name == "nt" else ":"
        entries = classpath.split(sep)
    else:
        entries = list(classpath or [])
    for entry in entries:
        if not entry or not entry.endswith(".jar") or not os.path.exists(entry):
            continue
        try:
            with zipfile.ZipFile(entry) as zf:
                for info in zf.namelist():
                    if info.endswith(".properties"):
                        text = zf.read(info).decode("utf-8", "replace")
                        if _WHITELIST_PROP_PREFIX in text:
                            flt = from_jasperreports(text)
                            if flt:
                                logger.info("Auto-extracted deserialization whitelist from %s!%s",
                                            entry, info)
                                return flt
        except Exception as exc:
            logger.warning("from_classpath: cannot read %s (%s)", entry, exc)
    return None


def load_filter(spec: Optional[str]) -> Optional["DeserializationFilter"]:
    """Explicit override: a JEP 290 pattern string, or a path to a file holding
    jasperreports properties or a JEP 290 string."""
    if not spec:
        return None
    import os
    if os.path.exists(spec):
        text = open(spec, "r", encoding="utf-8").read()
        jr = from_jasperreports(text)
        if jr:
            return jr
        return from_jep290(text.strip())
    return from_jep290(spec)
