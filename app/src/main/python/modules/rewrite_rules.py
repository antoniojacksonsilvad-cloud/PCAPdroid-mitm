import os
import re
import sys
import xml.etree.ElementTree as ET

# allow running this file directly (the CI test step does), while the addon
# itself imports it as part of the "modules" package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""
A regular expression substitution applied to a value (a body, a header, ...).
"""
class Substitution:
    def __init__(self, pattern: str, replacement: str, replace_first: bool = False):
        self.pattern = pattern
        self.regex = re.compile(pattern)
        self.replacement = replacement
        self.replace_first = replace_first

    def apply(self, text: str) -> str:
        if self.replace_first:
            return self.regex.sub(self.replacement, text, count=1)
        return self.regex.sub(self.replacement, text)

    def __str__(self):
        op = "first" if self.replace_first else "all"
        return self.pattern + " => " + (self.replacement or "<vazio>") + " (" + op + ")"


"""
A rule to rewrite an HTTP(S) request or response matching a URL pattern.

The pattern is a Python regular expression matched against the full request
URL (e.g. https://example.com/v1/user?x=1). Any field left as None is not
modified, so a rule can change just the status, just some headers, or just
the body.

The same class holds the rules imported from the Charles Proxy format, which
can also target the request and can remove headers/query parameters.
"""
class RewriteRule:
    def __init__(self, pattern: str = None, status=None, headers=None, body=None,
                 host: str = None, scope: str = "response",
                 remove_headers=None, body_subs=None,
                 query_add=None, query_remove=None, url_subs=None,
                 type_name: str = None, set_name: str = None):
        self.pattern = pattern
        # the URL pattern is optional: a rule may only constrain the host
        self.regex = re.compile(pattern) if pattern else None
        self.host = host
        self.host_regex = re.compile(host) if host else None
        # "request" or "response"
        self.scope = scope
        self.status = status
        self.headers = headers if headers is not None else {}
        self.body = body
        self.remove_headers = remove_headers if remove_headers is not None else []
        self.body_subs = body_subs if body_subs is not None else []
        self.query_add = query_add if query_add is not None else {}
        self.query_remove = query_remove if query_remove is not None else []
        self.url_subs = url_subs if url_subs is not None else []
        # only for display/debug
        self.type_name = type_name
        self.set_name = set_name

    def applies_to(self, which: str) -> bool:
        """True when the rule must be applied to the given side of the
        exchange, "request" or "response"."""
        return (self.scope == "both") or (self.scope == which)

    def matches(self, url: str, host: str = None) -> bool:
        if (self.regex is None) and (self.host_regex is None):
            return False

        if self.host_regex is not None:
            if (host is None) or (self.host_regex.search(host) is None):
                return False

        if self.regex is None:
            return True

        # use search() so that a pattern can match anywhere in the URL, and a
        # fully anchored pattern still works
        return self.regex.search(url) is not None

    def __repr__(self):
        return self.pattern if self.pattern else (self.host or "?")

    def __str__(self):
        rv = "[" + self.scope + "] "

        if self.host:
            rv += "host=" + self.host + " "

        rv += "pattern=" + str(self.pattern)

        if self.type_name:
            rv += " type=" + self.type_name

        if self.status is not None:
            rv += " status=" + str(self.status)
        if self.headers:
            rv += " headers=" + ",".join(self.headers.keys())
        if self.remove_headers:
            rv += " rm-headers=" + ",".join(self.remove_headers)
        if self.query_add:
            rv += " add-query=" + ",".join(self.query_add.keys())
        if self.query_remove:
            rv += " rm-query=" + ",".join(self.query_remove)
        if self.url_subs:
            rv += " url=" + str(len(self.url_subs)) + "sub"
        if self.body is not None:
            rv += " body=" + str(len(self.body)) + "B"
        if self.body_subs:
            rv += " body=" + str(len(self.body_subs)) + "sub"

        if self.set_name:
            rv += " set=" + self.set_name

        return rv


"""
Parses the rewrite rules XML.

Accepted formats (the <rewrite> element is optional, its children can be
placed directly inside <rule>):

    <rules>
        <rule>
            <pattern>https://example.com/v1/user</pattern>
            <rewrite>
                <status_code>200</status_code>
                <headers>
                    <header name="X-Custom" value="Test"/>
                </headers>
                <body>{"status": "ok"}</body>
            </rewrite>
        </rule>
    </rules>

A document whose root is a single <rule> is also accepted.
"""
class XmlRuleParser:
    @staticmethod
    def parse(xml_content: str) -> list:
        if not xml_content or not xml_content.strip():
            return []

        try:
            # NOTE: encode to bytes, otherwise ElementTree rejects the string
            # when it contains an "<?xml ... encoding=...?>" declaration
            root = ET.fromstring(xml_content.encode("utf-8"))
        except ET.ParseError as e:
            raise ValueError("Invalid XML: " + str(e))

        rules = []

        if XmlRuleParser._localname(root.tag) == "rule":
            # the root is a single rule
            rule_elems = [root]
        else:
            rule_elems = root.iter("rule")

        for rule_elem in rule_elems:
            rule = XmlRuleParser._parse_rule(rule_elem)
            if rule is not None:
                rules.append(rule)

        return rules

    @staticmethod
    def _parse_rule(elem) -> RewriteRule:
        pattern = XmlRuleParser._get_text(elem, "pattern")
        if not pattern:
            return None

        # the <rewrite> element is optional
        container = elem.find("rewrite")
        if container is None:
            container = elem

        status = None
        # accept both <status_code> and <status>
        status_str = XmlRuleParser._get_text(container, "status_code")
        if status_str is None:
            status_str = XmlRuleParser._get_text(container, "status")
        if status_str:
            try:
                status = int(status_str)
            except ValueError:
                raise ValueError("Invalid status code \"" + status_str +
                                 "\" for pattern " + pattern)

        headers = {}
        headers_elem = container.find("headers")
        if headers_elem is not None:
            for header in headers_elem.findall("header"):
                name = header.get("name")
                if not name:
                    continue
                headers[name] = header.get("value", "")

        body = XmlRuleParser._get_text(container, "body", keep_whitespace=True)

        try:
            return RewriteRule(pattern, status, headers, body)
        except re.error as e:
            # NOTE: on Python 3.13+ this is re.PatternError, which does not
            # derive from ValueError
            raise ValueError("Invalid pattern \"" + pattern + "\": " + str(e))

    @staticmethod
    def _get_text(elem, name: str, keep_whitespace: bool = False):
        child = elem.find(name)
        if child is None:
            return None

        # supports CDATA sections and nested elements
        text = "".join(child.itertext())

        if keep_whitespace:
            # when the XML is pretty-printed, the body is wrapped in the
            # indentation newlines: drop the whitespace surrounding it, but
            # keep the internal formatting of the body as it is
            if text.startswith("\n"):
                text = text.strip()
        else:
            text = text.strip()

        return text

    @staticmethod
    def _localname(tag: str) -> str:
        # drop the namespace, if any (e.g. {http://...}rule)
        if isinstance(tag, str) and tag.startswith("{"):
            return tag.split("}", 1)[1]
        return tag


"""
Parses a rules document, detecting its format from the root element.

Supported roots:
  <rules> / <rule>          the native PCAPdroid format
  <rewriteSet-array>        the Charles Proxy rewrite format

Raises ValueError if the document is neither.
"""
def parse_rules(xml_content: str) -> list:
    if not xml_content or not xml_content.strip():
        return []

    root_name = document_root(xml_content)
    if root_name == "rewriteSet-array":
        # imported here, the Charles parser builds on top of this module
        from modules.charles_rules import CharlesRuleParser
        return CharlesRuleParser.parse(xml_content)

    if root_name in ("rules", "rule"):
        return XmlRuleParser.parse(xml_content)

    raise ValueError("Unrecognized rewrite rules format, the root element is <"
                     + str(root_name) + ">")


def document_root(xml_content: str) -> str:
    """Returns the local name of the document root element, without parsing
    the whole document. Raises ValueError on a malformed document."""
    try:
        # encode to bytes, otherwise ElementTree rejects the string when it
        # contains an "<?xml ... encoding=...?>" declaration
        root = ET.fromstring(xml_content.encode("utf-8"))
    except ET.ParseError as e:
        raise ValueError("Invalid XML: " + str(e))

    return XmlRuleParser._localname(root.tag)

if __name__ == "__main__":
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <rules>
        <rule>
            <pattern>https://api\\.exemplo\\.com/v1/usuario</pattern>
            <rewrite>
                <status_code>200</status_code>
                <headers><header name="X-Custom-Header" value="Teste"/></headers>
                <body>{"status": "sucesso"}</body>
            </rewrite>
        </rule>
        <rule>
            <pattern>^https://exemplo\\.com/flag$</pattern>
            <status>404</status>
            <body>
                {"pretty": true}
            </body>
        </rule>
    </rules>"""

    rules = XmlRuleParser.parse(xml)
    assert(len(rules) == 2)

    r = rules[0]
    assert(r.pattern == "https://api\\.exemplo\\.com/v1/usuario")
    assert(r.status == 200)
    assert(r.headers == {"X-Custom-Header": "Teste"})
    assert(r.body == '{"status": "sucesso"}')
    assert(r.matches("https://api.exemplo.com/v1/usuario?x=1"))
    assert(not r.matches("https://api.exemplo.com/v1/outro"))

    # <rewrite> omitted
    r = rules[1]
    assert(r.status == 404)
    assert(r.headers == {})
    assert(r.body == '{"pretty": true}')
    assert(r.matches("https://exemplo.com/flag"))
    assert(not r.matches("https://exemplo.com/flagged"))

    # only the whitespace surrounding the body is dropped, the internal
    # formatting is kept as it is
    rules = XmlRuleParser.parse("<rules><rule>"
            + "<pattern>x</pattern>"
            + "<body>\n  {\n    \"a\": 1\n  }\n</body>"
            + "</rule></rules>")
    assert(rules[0].body == "{\n    \"a\": 1\n  }")

    # a single <rule> as document root
    rules = XmlRuleParser.parse("""<rule>
        <pattern>https://exemplo.com/</pattern>
        <rewrite><body>ok</body></rewrite>
    </rule>""")
    assert(len(rules) == 1)
    assert(rules[0].body == "ok")
    assert(rules[0].status is None)

    # empty input
    assert(XmlRuleParser.parse("") == [])
    assert(XmlRuleParser.parse("   ") == [])

    # rules with no pattern are skipped
    assert(XmlRuleParser.parse("<rules><rule><body>x</body></rule></rules>") == [])

    # CDATA body
    rules = XmlRuleParser.parse("""<rules><rule>
        <pattern>x</pattern><body><![CDATA[{"a": 1}]]></body>
    </rule></rules>""")
    assert(rules[0].body == '{"a": 1}')

    # invalid regex is reported
    try:
        XmlRuleParser.parse("<rules><rule><pattern>[unclosed</pattern></rule></rules>")
        assert(False)
    except ValueError:
        pass

    # invalid XML is reported
    try:
        XmlRuleParser.parse("<rules>")
        assert(False)
    except ValueError:
        pass

    # ----- format detection

    # the native format is still detected and parsed
    rules = parse_rules("<rules><rule><pattern>x</pattern><status_code>200</status_code>"
                        + "</rule></rules>")
    assert(len(rules) == 1)
    assert(rules[0].status == 200)
    assert(rules[0].scope == "response")

    # the Charles format is detected and parsed
    rules = parse_rules("""<rewriteSet-array><rewriteSet>
        <active>true</active><name>S</name>
        <hosts><locationPatterns/></hosts>
        <rules><rewriteRule>
            <active>true</active><ruleType>7</ruleType>
            <matchValue>x</matchValue><matchValueRegex>true</matchValueRegex>
            <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
            <newValue>y</newValue><replaceType>2</replaceType>
        </rewriteRule></rules>
    </rewriteSet></rewriteSet-array>""")
    assert(len(rules) == 1)
    assert(rules[0].scope == "request")
    assert(rules[0].type_name == "BODY")

    # an unknown root is rejected
    try:
        parse_rules("<outro><a/></outro>")
        assert(False)
    except ValueError:
        pass

    # a malformed document is rejected
    try:
        parse_rules("<rules>")
        assert(False)
    except ValueError:
        pass

    # empty input
    assert(parse_rules("") == [])
    assert(parse_rules("  ") == [])

    print("All tests passed")
