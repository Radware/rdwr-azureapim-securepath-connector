#!/usr/bin/env python3
"""Render the whole-document install form (README Form 3) from the three
policy fragments, so the fragments stay the single source.

    python3 tools/build_documents.py            # writes rdwr-azureapim-securepath-connector-v1.5.xml
    python3 tools/build_documents.py --check    # exit 1 if the document on disk is stale

Text-based on purpose: policy documents are not well-formed XML.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
VERSION = "1.5"
OUT = os.path.join(ROOT, f"rdwr-azureapim-securepath-connector-v{VERSION}.xml")
FRAGMENTS = {
    "inbound": "securepath-inbound.fragment.xml",
    "outbound": "securepath-outbound.fragment.xml",
    "on-error": "securepath-onerror.fragment.xml",
}
HEADER = (
    "<!-- Radware SecurePath Connector for Azure API Management, v{v}.0 (policy document, API scope).\n"
    "     GENERATED from fragments/ by tools/build_documents.py. Edit the fragments, then re-run\n"
    "     the tool. The fragments are the recommended install (README Step 4, Form 1); this\n"
    "     document is for an API that has no policy of its own (Form 3). -->\n"
)


def fragment_body(name):
    with open(os.path.join(ROOT, "fragments", FRAGMENTS[name]), encoding="utf-8") as f:
        text = f.read()
    start = text.index("<fragment>") + len("<fragment>")
    end = text.rindex("</fragment>")
    body = text[start:end].strip("\n")
    return "\n".join(("    " + ln) if ln.strip() else "" for ln in body.splitlines())


def render():
    inbound = fragment_body("inbound")
    assert "include-fragment" not in inbound, "the whole document must not reference fragments"
    return (
        HEADER.format(v=VERSION)
        + "<policies>\n"
        + "    <inbound>\n        <base />\n" + inbound + "\n    </inbound>\n"
        + "    <backend>\n        <base />\n    </backend>\n"
        + "    <outbound>\n        <base />\n" + fragment_body("outbound") + "\n    </outbound>\n"
        + "    <on-error>\n        <base />\n" + fragment_body("on-error") + "\n    </on-error>\n"
        + "</policies>\n"
    )


def main(argv=None):
    check = "--check" in (argv or sys.argv[1:])
    doc = render()
    if check:
        try:
            with open(OUT, encoding="utf-8") as f:
                stale = f.read() != doc
        except OSError:
            stale = True
        print("stale" if stale else "up to date", OUT)
        return 1 if stale else 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"wrote {OUT} ({len(doc.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
