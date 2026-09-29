#
#  This file is part of PCAPdroid.
#
#  PCAPdroid is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  PCAPdroid is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
#
#  Copyright 2026 - antoniojacksonsilvad-cloud
#

import os
import re
import sys
import xml.etree.ElementTree as ET

# allow running this file directly (the CI test step does), while the addon
# itself imports it as part of the "modules" package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.rewrite_rules import RewriteRule, Substitution  # noqa: E402

"""
Parser for the Charles Proxy rewrite format.

    <?charles serialisation-version='2.0' ?>
    <rewriteSet-array>
      <rewriteSet>
        <active>true</active>
        <name>My set</name>
        <hosts>
          <locationPatterns>
            <locationMatch>
              <location>api\\.example\\.com</location>
              <enabled>true</enabled>
            </locationMatch>
          </locationPatterns>
        </hosts>
        <rules>
          <rewriteRule>
            <active>true</active>
            <ruleType>7</ruleType>
            <matchValue>&amp;SecurityCode=\\d+</matchValue>
            <matchValueRegex>true</matchValueRegex>
            <matchRequest>true</matchRequest>
            <matchResponse>false</matchResponse>
            <newValue></newValue>
            <replaceType>2</replaceType>
          </rewriteRule>
        </rules>
      </rewriteSet>
    </rewriteSet-array>
"""

# the numeric ruleType mapping, as used by Charles when it serialises the
# rewrite sets. Taken from the RewriteType enum of the Niddler project
# (Chimerapps/niddler-ui, Model.kt), which is the only open source
# implementation of this format found.
RULE_TYPES = {
    1: "ADD_HEADER",
    2: "REMOVE_HEADER",
    3: "MODIFY_HEADER",
    4: "HOST",
    5: "PATH",
    6: "URL",
    7: "BODY",
    8: "ADD_QUERY_PARAM",
    9: "MODIFY_QUERY_PARAM",
    10: "REMOVE_QUERY_PARAM",
    11: "RESPONSE_STATUS",
}

# the numeric replaceType mapping
REPLACE_FIRST = 1
REPLACE_ALL = 2

# A real Charles export, used by the self-tests below. It strips the
# "SecurityCode" field from the body of every outgoing request.
SAMPLE_XML = """<?xml version='1.0' encoding='UTF-8' ?>
<?charles serialisation-version='2.0' ?>
<rewriteSet-array>
  <rewriteSet>
    <active>true</active>
    <name>CieloNuvem @tramposvipdomagoreferencias</name>
    <hosts>
      <locationPatterns>
        <locationMatch>
          <location/>
          <enabled>true</enabled>
        </locationMatch>
      </locationPatterns>
    </hosts>
    <rules>
      <rewriteRule>
        <active>true</active>
        <ruleType>7</ruleType>
        <matchValue>&amp;SecurityCode=\\d+</matchValue>
        <matchHeaderRegex>false</matchHeaderRegex>
        <matchValueRegex>true</matchValueRegex>
        <matchRequest>true</matchRequest>
        <matchResponse>false</matchResponse>
        <newValue></newValue>
        <newHeaderRegex>false</newHeaderRegex>
        <newValueRegex>false</newValueRegex>
        <matchWholeValue>false</matchWholeValue>
        <caseSensitive>false</caseSensitive>
        <replaceType>2</replaceType>
      </rewriteRule>
    </rules>
  </rewriteSet>
</rewriteSet-array>"""


class CharlesRuleParser:
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

        if CharlesRuleParser._localname(root.tag) != "rewriteSet-array":
            raise ValueError("Not a Charles rewrite file")

        rules = []

        for set_elem in root.iter("rewriteSet"):
            # an inactive set is ignored entirely
            if not CharlesRuleParser._bool(set_elem, "active", default=True):
                continue

            set_name = CharlesRuleParser._text(set_elem, "name")
            hosts = CharlesRuleParser._parse_hosts(set_elem)

            for rule_elem in set_elem.iter("rewriteRule"):
                # a rule is built for each host of the set, so this returns a list
                rules.extend(CharlesRuleParser._parse_rule(rule_elem, hosts, set_name))

        return rules

    # ----- the rewrite set

    @staticmethod
    def _parse_hosts(set_elem) -> list:
        """The host patterns the set applies to. An empty list means any host."""
        hosts = []

        for match_elem in set_elem.iter("locationMatch"):
            if not CharlesRuleParser._bool(match_elem, "enabled", default=True):
                continue

            location = CharlesRuleParser._text(match_elem, "location")
            if location:
                hosts.append(location)

        return hosts

    # ----- a single rule

    @staticmethod
    def _parse_rule(elem, hosts: list, set_name: str) -> list:
        if not CharlesRuleParser._bool(elem, "active", default=True):
            return []

        type_code = CharlesRuleParser._int(elem, "ruleType")
        if type_code is None:
            return []

        type_name = RULE_TYPES.get(type_code, "TYPE_" + str(type_code))

        scope = CharlesRuleParser._parse_scope(elem)

        match_value = CharlesRuleParser._text(elem, "matchValue", default="") or ""
        new_value = CharlesRuleParser._text(elem, "newValue", default="") or ""
        match_header = CharlesRuleParser._text(elem, "matchHeader", default="") or ""
        new_header = CharlesRuleParser._text(elem, "newHeader", default="") or ""

        # a regex is assumed unless the rule explicitly says it is a literal
        value_is_regex = CharlesRuleParser._bool(elem, "matchValueRegex", default=False)
        replace_first = (CharlesRuleParser._int(elem, "replaceType", REPLACE_ALL)
                         == REPLACE_FIRST)

        # the rules are shared by all the hosts of the set: a rule is built for
        # each of them, plus one without host constraint when the set has none
        targets = hosts if hosts else [None]

        rules = []
        for host in targets:
            try:
                rule = CharlesRuleParser._build(type_code, type_name, scope, host,
                                                set_name, match_value, new_value,
                                                match_header, new_header,
                                                value_is_regex, replace_first,
                                                elem)
            except re.error as e:
                # NOTE: on Python 3.13+ this is re.PatternError, which does not
                # derive from ValueError
                raise ValueError("Invalid pattern \"" + match_value + "\" in rule \""
                                 + type_name + "\": " + str(e))

            if rule is not None:
                rules.append(rule)

        return rules

    @staticmethod
    def _build(type_code, type_name, scope, host, set_name, match_value, new_value,
               match_header, new_header, value_is_regex, replace_first, elem):
        status = None
        headers = {}
        remove_headers = []
        body = None
        body_subs = None
        query_add = {}
        query_remove = []
        url_subs = None

        if type_code == 1:
            # ADD_HEADER: the header is added to every matching message
            name = new_header if new_header else match_header
            if name:
                headers[name] = new_value

        elif type_code == 2:
            # REMOVE_HEADER
            if match_header:
                remove_headers.append(match_header)

        elif type_code == 3:
            # MODIFY_HEADER: only the value is changed, the name is kept
            if match_header:
                headers[match_header] = new_value

        elif type_code in (4, 5, 6):
            # HOST / PATH / URL: a substitution on the corresponding URL part
            if match_value:
                url_subs = [Substitution(match_value, new_value, replace_first)]

        elif type_code == 7:
            # BODY
            if value_is_regex:
                if match_value:
                    body_subs = [Substitution(match_value, new_value, replace_first)]
            elif match_value:
                # a literal search and replace, escaped so that it is not
                # interpreted as a regular expression
                body_subs = [Substitution(re.escape(match_value), new_value, replace_first)]
            else:
                # no match value: the whole body is replaced
                body = new_value

        elif type_code == 8:
            # ADD_QUERY_PARAM
            if match_value:
                query_add[match_value] = new_value

        elif type_code == 9:
            # MODIFY_QUERY_PARAM
            if match_value:
                query_add[match_value] = new_value

        elif type_code == 10:
            # REMOVE_QUERY_PARAM
            if match_value:
                query_remove.append(match_value)

        elif type_code == 11:
            # RESPONSE_STATUS
            try:
                status = int(new_value)
            except ValueError:
                raise ValueError("Invalid status code \"" + new_value +
                                 "\" in rule \"RESPONSE_STATUS\"")

        else:
            # an unknown type: keep it visible in the app but do not apply it,
            # applying a rule we do not understand could corrupt the traffic
            print("Unsupported Charles rule type: " + str(type_code) +
                  " (" + type_name + "), skipped")
            return None

        if (status is None and not headers and not remove_headers and body is None
                and body_subs is None and not query_add and not query_remove
                and not url_subs):
            # nothing to do
            return None

        return RewriteRule(pattern=None, host=host, scope=scope, status=status,
                           headers=headers, body=body,
                           remove_headers=remove_headers, body_subs=body_subs,
                           query_add=query_add, query_remove=query_remove,
                           url_subs=url_subs,
                           type_name=type_name, set_name=set_name)

    @staticmethod
    def _parse_scope(elem) -> str:
        """Which side of the exchange the rule applies to."""
        on_request = CharlesRuleParser._bool(elem, "matchRequest", default=False)
        on_response = CharlesRuleParser._bool(elem, "matchResponse", default=False)

        if on_request and on_response:
            return "both"
        if on_request:
            return "request"

        # Charles defaults to the response when neither flag is set
        return "response"

    # ----- helpers

    @staticmethod
    def _text(elem, name: str, default=None):
        child = elem.find(name)
        if child is None:
            return default

        # supports CDATA sections and nested elements
        text = "".join(child.itertext()).strip()
        return text if text else default

    @staticmethod
    def _bool(elem, name: str, default: bool = False) -> bool:
        value = CharlesRuleParser._text(elem, name)
        if value is None:
            return default
        return value.strip().lower() == "true"

    @staticmethod
    def _int(elem, name: str, default=None):
        value = CharlesRuleParser._text(elem, name)
        if value is None:
            return default

        try:
            return int(value)
        except ValueError:
            return default

    @staticmethod
    def _localname(tag: str) -> str:
        # drop the namespace, if any (e.g. {http://...}rewriteSet-array)
        if isinstance(tag, str) and tag.startswith("{"):
            return tag.split("}", 1)[1]
        return tag


if __name__ == "__main__":
    rules = CharlesRuleParser.parse(SAMPLE_XML)
    assert(len(rules) == 1), "expected 1 rule, got " + str(len(rules))

    r = rules[0]
    print("  scope      =", r.scope)
    print("  type       =", r.type_name)
    print("  host       =", r.host)
    print("  body_subs  =", [str(s) for s in r.body_subs])
    print("  set        =", r.set_name)

    assert(r.scope == "request")
    assert(r.type_name == "BODY")
    assert(r.host is None)  # <location/> is empty: any host
    assert(len(r.body_subs) == 1)
    assert(r.body_subs[0].pattern == "&SecurityCode=\\d+")
    assert(r.body_subs[0].replacement == "")
    assert(not r.body_subs[0].replace_first)

    # the substitution removes every occurrence from a form body
    body = "user=joao&SecurityCode=1234&SecurityCode=5678&x=1"
    out = r.body_subs[0].apply(body)
    assert(out == "user=joao&x=1"), "got " + out

    # a rule with a host pattern only applies to that host
    xml_host = """<?xml version='1.0' encoding='UTF-8' ?>
    <rewriteSet-array><rewriteSet>
      <active>true</active><name>S</name>
      <hosts><locationPatterns><locationMatch>
        <location>api\\.exemplo\\.com</location><enabled>true</enabled>
      </locationMatch></locationPatterns></hosts>
      <rules><rewriteRule>
        <active>true</active><ruleType>7</ruleType>
        <matchValue>"vip":false</matchValue><matchValueRegex>false</matchValueRegex>
        <matchRequest>false</matchRequest><matchResponse>true</matchResponse>
        <newValue>"vip":true</newValue><replaceType>2</replaceType>
      </rewriteRule></rules>
    </rewriteSet></rewriteSet-array>"""
    rules = CharlesRuleParser.parse(xml_host)
    assert(len(rules) == 1)
    r = rules[0]
    assert(r.host == "api\\.exemplo\\.com")
    assert(r.scope == "response")
    assert(r.matches("https://api.exemplo.com/x", "api.exemplo.com"))
    assert(not r.matches("https://api.exemplo.com/x", "outro.com"))

    # header rules
    xml_hdr = """<rewriteSet-array><rewriteSet>
      <active>true</active><name>S</name>
      <hosts><locationPatterns/></hosts>
      <rules>
        <rewriteRule>
          <active>true</active><ruleType>3</ruleType>
          <matchHeader>Content-Type</matchHeader>
          <matchValue>application/json</matchValue>
          <newValue>text/plain</newValue>
          <matchRequest>false</matchRequest><matchResponse>true</matchResponse>
          <replaceType>2</replaceType>
        </rewriteRule>
        <rewriteRule>
          <active>true</active><ruleType>2</ruleType>
          <matchHeader>X-Tracking</matchHeader>
          <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
        </rewriteRule>
        <rewriteRule>
          <active>true</active><ruleType>11</ruleType>
          <newValue>204</newValue>
          <matchResponse>true</matchResponse>
        </rewriteRule>
      </rules>
    </rewriteSet></rewriteSet-array>"""
    rules = CharlesRuleParser.parse(xml_hdr)
    assert(len(rules) == 3)
    assert(rules[0].headers == {"Content-Type": "text/plain"})
    assert(rules[1].remove_headers == ["X-Tracking"])
    assert(rules[1].scope == "request")
    assert(rules[2].status == 204)

    # an inactive set / rule is skipped
    assert(CharlesRuleParser.parse(
        '<rewriteSet-array><rewriteSet><active>false</active>'
        '<rules><rewriteRule><ruleType>7</ruleType></rewriteRule></rules>'
        '</rewriteSet></rewriteSet-array>') == [])

    # not a Charles document
    try:
        CharlesRuleParser.parse("<rules><rule/></rules>")
        assert(False)
    except ValueError:
        pass

    print("All Charles parser tests passed")
