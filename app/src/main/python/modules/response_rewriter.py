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
from modules.rewrite_rules import parse_rules

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
    per enabled file. Both the native format and the Charles Proxy format are
    accepted, the format is detected from the root element of the document. A
    document which cannot be parsed is skipped, so that a single bad file does
    not disable all the others.
    """
    def load(self, rules_xmls):
        rules = []

        if rules_xmls is None:
            rules_xmls = []

        for xml in rules_xmls:
            if not xml:
                continue

            try:
                rules.extend(parse_rules(xml))
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
        host = flow.request.host

        for rule in self.rules:
            if rule.applies_to("response") and rule.matches(url, host):
                # the first matching rule wins
                self.rewrite(rule, flow)
                return

    def rewrite(self, rule, flow: http.HTTPFlow):
        response = flow.response
        url = flow.request.pretty_url
        applied = []

        if rule.status is not None:
            response.status_code = rule.status
            applied.append("status=" + str(rule.status))

        self.apply_headers(rule, response, applied)
        self.apply_body(rule, response, applied)

        if applied:
            print("[" + str(response.status_code) + "] rewritten " + url +
                  " (" + ", ".join(applied) + ")")

    # ----- actions shared by the request and the response rewriting

    def apply_headers(self, rule, message, applied: list):
        for name in rule.remove_headers:
            if message.headers.pop(name, None) is not None:
                applied.append("rm-header=" + name)

        if rule.headers:
            for name, value in rule.headers.items():
                message.headers[name] = value
            applied.append("headers=" + ",".join(rule.headers.keys()))

    def apply_body(self, rule, message, applied: list):
        """Applies the body actions of a rule: either a full replacement or a
        list of regular expression substitutions."""
        if rule.body is not None:
            # the rule body is plain text, so the original content encoding no
            # longer applies: drop it, otherwise the client would try to
            # decompress the new body. content-length is updated by mitmproxy
            # when setting the content.
            message.headers.pop("content-encoding", None)
            message.headers.pop("transfer-encoding", None)
            message.text = rule.body
            applied.append("body=" + str(len(message.content)) + "B")
            return

        if not rule.body_subs:
            return

        # the substitutions run on the decoded text, so the body can be
        # compressed: the text setter of mitmproxy re-encodes it and updates
        # the content-length
        original = message.get_text(strict=False)
        if original is None:
            return

        new = original
        for sub in rule.body_subs:
            new = sub.apply(new)

        if new == original:
            # nothing matched, leave the body alone so that the original
            # content and its encoding are preserved untouched
            return

        message.text = new
        applied.append("body=" + str(len(message.content)) + "B (" +
                       ",".join(str(s) for s in rule.body_subs) + ")")
