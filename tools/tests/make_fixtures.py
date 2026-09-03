#!/usr/bin/env python3
"""Regenerate fixtures/merged_jwt_first.xml: the shipped policy document with a
validate-jwt block merged in ahead of the connector and the block-page
set-variable emptied. This is the shape a manual merge produces."""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "..", "rdwr-azureapim-securepath-connector-v1.3.xml")
OUT = os.path.join(HERE, "fixtures", "merged_jwt_first.xml")
JWT = """        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized">
            <openid-config url="https://login.example.com/tenant/v2.0/.well-known/openid-configuration" />
            <audiences>
                <audience>00000000-0000-0000-0000-000000000000</audience>
            </audiences>
            <issuers>
                <issuer>https://login.example.com/tenant/v2.0/</issuer>
            </issuers>
        </validate-jwt>
        <set-backend-service backend-id="example-pool" />
"""


def main():
    with open(SRC, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"<inbound>\s*\n(\s*<base\s*/>[ \t]*\n)", text)
    text = text[:m.end(1)] + JWT + text[m.end(1):]
    text = re.sub(r'<set-variable name="rdwrRenderedBlockPage" value="@\{.*?\}" />',
                  '<set-variable name="rdwrRenderedBlockPage" />', text, count=1, flags=re.S)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote", OUT, len(text.splitlines()), "lines")


if __name__ == "__main__":
    main()
