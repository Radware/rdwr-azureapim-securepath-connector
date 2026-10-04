"""Element-structure checks that API Management performs when a fragment or policy is saved.

API Management stopped accepting a <choose> as a direct child of <send-request> and
<send-one-way-request> between 2026-09-24 and 2026-10-04 (every tier). A fragment that breaks the
rule is refused when it is registered, and an instance that still carries one refuses every change
to a Named Value that fragment references. These tests read the element tree the way the gateway
does: policy expressions (@(...) and @{...}) are masked first, because they contain raw quotes and
angle brackets, so the documents are not well-formed XML.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
FRAGMENTS = ["fragments/securepath-%s.fragment.xml" % n for n in ("app-map", "inbound", "outbound", "onerror")]
DOCUMENTS = ["rdwr-azureapim-securepath-connector-v1.5.xml"]
SEND_CHILDREN = {"set-url", "set-method", "set-header", "set-body", "authentication-certificate",
                 "authentication-token", "authentication-token-store", "authentication-managed-identity",
                 "proxy"}


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _skip_string(s, i):
    """i points at the opening quote of a C# string or char literal; return the index after it."""
    if s[i] == "'":
        j = i + 1
        while s[j] != "'":
            j += 2 if s[j] == "\\" else 1
        return j + 1
    verbatim = i > 0 and s[i - 1] == "@"
    j = i + 1
    while True:
        if verbatim and s[j] == '"' and s[j + 1:j + 2] == '"':
            j += 2
        elif not verbatim and s[j] == "\\":
            j += 2
        elif s[j] == '"':
            return j + 1
        else:
            j += 1


def mask_expressions(s):
    """Replace every policy expression with spaces, keeping offsets (and so line numbers)."""
    out = list(s)
    i = 0
    n = len(s)
    while i < n:
        if s.startswith("<!--", i):
            i = s.index("-->", i) + 3
            continue
        if s[i] == "@" and i + 1 < n and s[i + 1] in "({":
            open_ch = s[i + 1]
            close_ch = ")" if open_ch == "(" else "}"
            depth = 0
            j = i + 1
            while True:
                c = s[j]
                if c in "\"'":
                    j = _skip_string(s, j)
                    continue
                if c == "/" and s[j + 1:j + 2] == "/":  # C# line comment (may hold an apostrophe)
                    nl = s.find("\n", j)
                    j = (nl if nl != -1 else n)
                    continue
                if c == "/" and s[j + 1:j + 2] == "*":  # C# block comment
                    j = s.index("*/", j) + 2
                    continue
                if c == open_ch:
                    depth += 1
                elif c == close_ch:
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            for k in range(i, j + 1):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(out)


TAG = re.compile(r"<(/?)([A-Za-z][\w.-]*)([^<>]*?)(/?)>")


def element_children(text, parent_names):
    """Yield (parent, line, [direct child element names]) for every element named in parent_names."""
    masked = re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), mask_expressions(text), flags=re.S)
    stack = []
    for m in TAG.finditer(masked):
        closing, name, _, selfclose = m.groups()
        if closing:
            top = stack.pop()
            assert top[0] == name, (top, name, masked.count("\n", 0, m.start()) + 1)
            if name in parent_names:
                yield name, top[1], top[2]
            continue
        if stack:
            stack[-1][2].append(name)
        if not selfclose:
            stack.append((name, masked.count("\n", 0, m.start()) + 1, []))
    assert not stack, stack


def test_masking_keeps_the_element_tree_balanced():
    for rel in FRAGMENTS + DOCUMENTS:
        list(element_children(read(rel), {"fragment", "policies"}))


def test_send_request_children_are_only_the_ones_api_management_accepts():
    for rel in FRAGMENTS + DOCUMENTS:
        seen = 0
        for parent, line, children in element_children(read(rel), {"send-request", "send-one-way-request"}):
            seen += 1
            bad = sorted(set(children) - SEND_CHILDREN)
            assert not bad, f"{rel}:{line}: <{parent}> has child element(s) {bad}, which API Management refuses at save"
        if "inbound" in rel or rel in DOCUMENTS:
            assert seen >= 7, (rel, seen)


def test_the_guard_catches_the_v140_shape():
    """Negative control: the v1.4.0 gating (a choose around a set-header inside send-request) is
    reported by the check above."""
    v140 = """<fragment><send-request mode="copy" response-variable-name="r">
      <set-url>@("https://x")</set-url>
      <choose><when condition="@((bool)context.Variables.GetValueOrDefault("p", false))">
        <set-header name="X-Rdwr-Partial-Body" exists-action="override"><value>true</value></set-header>
      </when></choose>
    </send-request></fragment>"""
    found = [c for _, _, c in element_children(v140, {"send-request"})]
    assert found == [["set-url", "choose"]]
