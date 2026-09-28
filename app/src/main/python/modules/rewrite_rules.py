import re
import xml.etree.ElementTree as ET

"""
A rule to rewrite an HTTP(S) response matching a URL pattern.

The pattern is a Python regular expression matched against the full request
URL (e.g. https://example.com/v1/user?x=1). Any field left as None is not
modified, so a rule can change just the status, just some headers, or just
the body.
"""
class RewriteRule:
    def __init__(self, pattern: str, status=None, headers=None, body=None):
        self.pattern = pattern
        self.regex = re.compile(pattern)
        self.status = status
        self.headers = headers if headers is not None else {}
        self.body = body

    def matches(self, url: str) -> bool:
        # use search() so that a pattern can match anywhere in the URL, and a
        # fully anchored pattern still works
        return self.regex.search(url) is not None

    def __repr__(self):
        return self.pattern

    def __str__(self):
        rv = "pattern=" + self.pattern
        if self.status is not None:
            rv += " status=" + str(self.status)
        if self.headers:
            rv += " headers=" + ",".join(self.headers.keys())
        if self.body is not None:
            rv += " body=" + str(len(self.body)) + "B"
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

    print("All tests passed")
