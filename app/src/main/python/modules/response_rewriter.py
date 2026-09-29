#!/usr/bin/env python3
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

from mitmproxy import http
from modules.rewrite_rules import XmlRuleParser

"""
Mitmproxy addon which rewrites the HTTP(S) responses matching the imported
XML rules. This operates on the real traffic: the modified response is what
gets forwarded to the client.
"""
class ResponseRewriter:
    def __init__(self, rules_xmls):
        self.rules = []
        self.load(rules_xmls)

    """
    Replaces the rules with the ones found in the given XML documents, one
    per enabled file. A document which cannot be parsed is skipped, so that a
    single bad file does not disable all the others.
    """
    def load(self, rules_xmls):
        rules = []

        if rules_xmls is None:
            rules_xmls = []

        for xml in rules_xmls:
            if not xml:
                continue

            try:
                rules.extend(XmlRuleParser.parse(xml))
            except Exception as e:
                # never prevent the proxy from running on a bad rules file
                print("Failed to parse a rewrite rules file: " + str(e))
                continue

        self.rules = rules

        for rule in self.rules:
            print("Loaded rewrite rule: " + str(rule))

        if not self.rules:
            print("No rewrite rules loaded")

    def response(self, flow: http.HTTPFlow):
        if not self.rules:
            return

        if flow.response is None:
            return

        # https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#HTTPFlow
        url = flow.request.pretty_url

        for rule in self.rules:
            if rule.matches(url):
                # the first matching rule wins
                self.rewrite(rule, flow)
                return

    def rewrite(self, rule, flow: http.HTTPFlow):
        response = flow.response
        applied = []

        if rule.status is not None:
            response.status_code = rule.status
            applied.append("status=" + str(rule.status))

        for name, value in rule.headers.items():
            response.headers[name] = value

        if rule.headers:
            applied.append("headers=" + ",".join(rule.headers.keys()))

        if rule.body is not None:
            # the rule body is plain text, so the original content encoding no
            # longer applies: drop it, otherwise the client would try to
            # decompress the new body. content-length is updated by mitmproxy
            # when setting the content.
            response.headers.pop("content-encoding", None)
            response.headers.pop("transfer-encoding", None)
            response.text = rule.body

            applied.append("body=" + str(len(response.content)) + "B")

        print("[" + str(response.status_code) + "] rewritten " + url +
              " (" + ", ".join(applied) + ")")
