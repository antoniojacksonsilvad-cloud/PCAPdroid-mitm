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
# Self-tests of the rewrite addon, run by the CI. mitmproxy is not available
# outside the addon APK, so the message objects are replaced by fakes which
# mimic the parts of the API the addon uses.

import sys, types, os

# stub out mitmproxy, which is not installed outside the addon APK
m = types.ModuleType("mitmproxy")
m.http = types.SimpleNamespace(HTTPFlow=object)
sys.modules["mitmproxy"] = m

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.response_rewriter import ResponseRewriter

class FakeHeaders(dict):
    def pop(self, k, d=None):
        return dict.pop(self, k, d)

class FakeResp:
    def __init__(self):
        self.status_code = 200
        self.headers = FakeHeaders({"content-encoding": "gzip", "server": "nginx"})
        self.content = b"old"
    # mimic mitmproxy: setting text updates the content and content-length
    @property
    def text(self):
        return self.content.decode()
    @text.setter
    def text(self, v):
        self.content = v.encode()
        self.headers["content-length"] = str(len(self.content))
    def get_text(self, strict=True):
        try:
            return self.content.decode()
        except UnicodeDecodeError:
            if strict:
                raise
            return None

class FakeQuery:
    """Mimics the mitmproxy MultiDictView: settable, readable with multi=True,
    and kept in sync with the URL query string."""
    def __init__(self, pairs, owner=None):
        object.__setattr__(self, "_pairs", list(pairs))
        object.__setattr__(self, "_owner", owner)

    @staticmethod
    def _parse(url):
        q = url.split("?", 1)[1] if "?" in url else ""
        out = []
        for part in q.split("&"):
            if not part:
                continue
            k, _, v = part.partition("=")
            out.append((k, v))
        return out

    @staticmethod
    def _build(pairs):
        return "&".join(k + "=" + v for k, v in pairs)

    @property
    def pairs(self):
        return self._pairs

    def items(self, multi=False):
        return list(self._pairs)

    @property
    def string(self):
        return self._build(self._pairs)

    def __setitem__(self, k, v):
        self._pairs.append((k, v))
        if self._owner is not None:
            self._owner._sync_url()


class FakeReq:
    def __init__(self, url, body=b"", method="POST", host=None):
        if host is None:
            host = url.split("/")[2] if "://" in url else ""
        self._url = url
        self.method = method
        self._host = host
        self.headers = FakeHeaders({"host": host, "content-type": "application/x-www-form-urlencoded"})
        self.content = body
        self._query = FakeQuery(FakeQuery._parse(url), self)

    @property
    def authority(self):
        # mitmproxy derives it from the URL, so it follows a host change
        return self._host

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, v):
        # assigning the URL re-derives the host and the query, as mitmproxy does
        self._url = v
        base = v.split("?", 1)[0]
        rest = v[len(base):]
        if "://" in base:
            self._host = base.split("://", 1)[1].split("/")[0]
        self._query = FakeQuery(FakeQuery._parse(rest), self)

    @property
    def pretty_url(self):
        return self._url

    @pretty_url.setter
    def pretty_url(self, v):
        self.url = v

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, v):
        self._host = v

    @property
    def query(self):
        return self._query

    @query.setter
    def query(self, pairs):
        # assigning to query rewrites the URL, as mitmproxy does
        if isinstance(pairs, list) and pairs and isinstance(pairs[0], tuple):
            self._query = FakeQuery(pairs, self)
        else:
            self._query = FakeQuery([(pairs, "")], self)
        self._sync_url()

    def _sync_url(self):
        base = self._url.split("?", 1)[0]
        q = self._query.string
        self._url = base + ("?" + q if q else "")

    @property
    def text(self):
        return self.content.decode()
    @text.setter
    def text(self, v):
        self.content = v.encode()
        self.headers["content-length"] = str(len(self.content))
    def get_text(self, strict=True):
        try:
            return self.content.decode()
        except UnicodeDecodeError:
            if strict:
                raise
            return None


class FakeFlow:
    def __init__(self, url, resp=None, host=None, body=b"", method="POST"):
        self.request = FakeReq(url, body, method, host)
        self.response = resp

XML_A = """<rules><rule>
    <pattern>https://api\\.exemplo\\.com/v1/usuario</pattern>
    <rewrite>
        <status_code>200</status_code>
        <headers><header name="X-Custom" value="A"/></headers>
        <body>{"status":"ok"}</body>
    </rewrite>
</rule></rules>"""

XML_B = """<rules>
    <rule>
        <pattern>^https://exemplo\\.com/flag$</pattern>
        <status>404</status>
    </rule>
    <rule>
        <pattern>https://exemplo\\.com/other</pattern>
        <body>outro</body>
    </rule>
</rules>"""

XML_BAD = "<rules><rule><pattern>[unclosed</pattern></rule></rules>"

# --- two valid files: the rules of both are merged
rw = ResponseRewriter([XML_A, XML_B])
assert len(rw.rules) == 3, "expected 3 rules, got " + str(len(rw.rules))

# --- matching + full rewrite
f = FakeFlow("https://api.exemplo.com/v1/usuario?x=1", FakeResp())
rw.response(f)
r = f.response
assert r.status_code == 200
assert r.headers["X-Custom"] == "A"
assert r.text == '{"status":"ok"}'
assert "content-encoding" not in r.headers, "content-encoding must be dropped"
assert r.headers["content-length"] == str(len(r.content))
assert r.headers["server"] == "nginx", "unrelated headers must be kept"

# --- second file, status only, no body -> content-encoding kept
f2 = FakeFlow("https://exemplo.com/flag", FakeResp())
rw.response(f2)
assert f2.response.status_code == 404
assert f2.response.text == "old", "no body rule must leave the body untouched"
assert "content-encoding" in f2.response.headers, "encoding kept when the body is not replaced"

# --- no match
f3 = FakeFlow("https://outro.com/x", FakeResp())
rw.response(f3)
assert f3.response.status_code == 200
assert f3.response.text == "old", "a non matching URL must be left untouched"

# --- response None
rw.response(FakeFlow("https://api.exemplo.com/v1/usuario", None))

# --- a bad file is skipped, the good ones still apply
rw2 = ResponseRewriter([XML_BAD, XML_B])
assert len(rw2.rules) == 2, "the bad file must be skipped, got " + str(len(rw2.rules))

# --- reload replaces the previous rules
rw.load([XML_B])
assert len(rw.rules) == 2
rw.load([])
assert rw.rules == []
rw.load(None)
assert rw.rules == []

# --- empty file skipped
rw.load(["", XML_A, None])
assert len(rw.rules) == 1

# --- a Charles response rule is applied
XML_CHARLES_RESP = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>VIP</name>
    <hosts><locationPatterns><locationMatch>
        <location>api\\.exemplo\\.com</location><enabled>true</enabled>
    </locationMatch></locationPatterns></hosts>
    <rules><rewriteRule>
        <active>true</active><ruleType>7</ruleType>
        <matchValue>"vip":false</matchValue><matchValueRegex>true</matchValueRegex>
        <matchRequest>false</matchRequest><matchResponse>true</matchResponse>
        <newValue>"vip":true</newValue><replaceType>2</replaceType>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rw3 = ResponseRewriter([XML_CHARLES_RESP])
assert len(rw3.rules) == 1, "expected 1 Charles rule, got " + str(len(rw3.rules))
assert rw3.rules[0].scope == "response"

# it rewrites the body when the host matches
f4 = FakeFlow("https://api.exemplo.com/v1/user", FakeResp())
f4.response.text = '{"vip":false,"n":1}'
rw3.response(f4)
assert f4.response.text == '{"vip":true,"n":1}', "got " + f4.response.text

# and leaves it alone on a different host
f5 = FakeFlow("https://outro.com/v1/user", FakeResp())
f5.response.text = '{"vip":false,"n":1}'
rw3.response(f5)
assert f5.response.text == '{"vip":false,"n":1}', "the host pattern must be honoured"

# --- a request-scoped rule must not touch the response
XML_CHARLES_REQ = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>VIP</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
        <active>true</active><ruleType>7</ruleType>
        <matchValue>&amp;SecurityCode=\\d+</matchValue>
        <matchValueRegex>true</matchValueRegex>
        <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
        <newValue></newValue><replaceType>2</replaceType>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rw4 = ResponseRewriter([XML_CHARLES_REQ])
assert len(rw4.rules) == 1
assert rw4.rules[0].scope == "request"

f6 = FakeFlow("https://api.exemplo.com/login", FakeResp())
f6.response.text = "resposta"
rw4.response(f6)
assert f6.response.text == "resposta", "a request rule must not rewrite the response"
assert f6.response.status_code == 200

# --- the Charles file of the user is accepted
rw5 = ResponseRewriter([XML_CHARLES_REQ])
assert len(rw5.rules) == 1
assert rw5.rules[0].body_subs[0].apply("u=1&SecurityCode=99&z=2") == "u=1&z=2"

# ============ REQUEST HOOK

# --- the user's actual rule: strip &SecurityCode= from the request body
XML_VIP = """<?xml version='1.0' encoding='UTF-8' ?>
<?charles serialisation-version='2.0' ?>
<rewriteSet-array>
  <rewriteSet>
    <active>true</active>
    <name>CieloNuvem @tramposvipdomagoreferencias</name>
    <hosts><locationPatterns><locationMatch>
      <location/><enabled>true</enabled>
    </locationMatch></locationPatterns></hosts>
    <rules><rewriteRule>
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
    </rewriteRule></rules>
  </rewriteSet>
</rewriteSet-array>"""
rwv = ResponseRewriter([XML_VIP])
assert len(rwv.rules) == 1, "expected 1 rule, got " + str(len(rwv.rules))

f = FakeFlow("https://api.exemplo.com/login",
             body=b"user=joao&SecurityCode=1234&pass=abc")
rwv.request(f)
assert f.request.get_text() == "user=joao&pass=abc", \
    "got " + repr(f.request.get_text())
assert f.request.headers["content-length"] == str(len(f.request.content)), \
    "content-length must be updated"

# every occurrence is removed (replaceType 2 = all)
f = FakeFlow("https://api.exemplo.com/login",
             body=b"a=1&SecurityCode=11&b=2&SecurityCode=22")
rwv.request(f)
assert f.request.get_text() == "a=1&b=2", "got " + repr(f.request.get_text())

# a request without the field is left byte-identical
f = FakeFlow("https://api.exemplo.com/login", body=b"user=joao&pass=abc")
before = f.request.content
rwv.request(f)
assert f.request.content == before, "a body without a match must not be touched"
assert "content-length" not in f.request.headers or \
       f.request.headers["content-length"] == str(len(before))

# a response rule must not fire on the request hook
rw6 = ResponseRewriter([XML_A])
f = FakeFlow("https://api.exemplo.com/v1/usuario", body=b"original")
rw6.request(f)
assert f.request.get_text() == "original", "a response rule must not touch the request"

# --- host scoping on the request side
XML_HOST_REQ = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns><locationMatch>
      <location>api\\.exemplo\\.com</location><enabled>true</enabled>
    </locationMatch></locationPatterns></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>7</ruleType>
      <matchValue>token=abc</matchValue><matchValueRegex>false</matchValueRegex>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
      <newValue>token=xyz</newValue><replaceType>2</replaceType>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwh = ResponseRewriter([XML_HOST_REQ])
f = FakeFlow("https://api.exemplo.com/a", body=b"token=abc")
rwh.request(f)
assert f.request.get_text() == "token=xyz", "got " + repr(f.request.get_text())

f = FakeFlow("https://outro.com/a", body=b"token=abc")
rwh.request(f)
assert f.request.get_text() == "token=abc", "the host pattern must be honoured"

# --- literal (non regex) body rule
XML_LITERAL = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>7</ruleType>
      <matchValue>a.c</matchValue><matchValueRegex>false</matchValueRegex>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
      <newValue>X</newValue><replaceType>2</replaceType>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwl = ResponseRewriter([XML_LITERAL])
f = FakeFlow("https://x.com/", body=b"abc a.c")
rwl.request(f)
# as a literal, the dot must not act as a wildcard
assert f.request.get_text() == "abc X", "got " + repr(f.request.get_text())

# --- remove header
XML_RM_HDR = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>2</ruleType>
      <matchHeader>X-Tracking</matchHeader>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwr = ResponseRewriter([XML_RM_HDR])
f = FakeFlow("https://x.com/", body=b"a")
f.request.headers["X-Tracking"] = "abc123"
rwr.request(f)
assert "X-Tracking" not in f.request.headers, "the header must be removed"
assert f.request.headers["host"] == "x.com", "unrelated headers must be kept"

# --- modify header value
XML_MOD_HDR = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>3</ruleType>
      <matchHeader>User-Agent</matchHeader>
      <matchValue>.*</matchValue><matchValueRegex>true</matchValueRegex>
      <newValue>MeuApp/1.0</newValue>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwm = ResponseRewriter([XML_MOD_HDR])
f = FakeFlow("https://x.com/", body=b"a")
f.request.headers["User-Agent"] = "Original/0"
rwm.request(f)
assert f.request.headers["User-Agent"] == "MeuApp/1.0"

# --- remove query param
XML_RM_Q = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>10</ruleType>
      <matchValue>SecurityCode</matchValue>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwq = ResponseRewriter([XML_RM_Q])
f = FakeFlow("https://x.com/api?a=1&SecurityCode=99&b=2", body=b"")
rwq.request(f)
assert "SecurityCode" not in f.request.pretty_url, "got " + f.request.pretty_url
assert "a=1" in f.request.pretty_url and "b=2" in f.request.pretty_url

# repeated params are all removed
f = FakeFlow("https://x.com/api?t=1&SecurityCode=a&t=2&SecurityCode=b", body=b"")
rwq.request(f)
assert "SecurityCode" not in f.request.pretty_url, "got " + f.request.pretty_url
assert f.request.pretty_url.endswith("t=1&t=2"), "got " + f.request.pretty_url

# --- add query param
XML_ADD_Q = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>8</ruleType>
      <matchValue>debug</matchValue>
      <newValue>1</newValue>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwa = ResponseRewriter([XML_ADD_Q])
f = FakeFlow("https://x.com/api?a=1", body=b"")
rwa.request(f)
assert "debug=1" in f.request.pretty_url, "got " + f.request.pretty_url
assert "a=1" in f.request.pretty_url, "the original query must be kept"

# --- URL substitution, with the Host header kept in sync
XML_URL = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>6</ruleType>
      <matchValue>^https://api\\.exemplo\\.com</matchValue>
      <matchValueRegex>true</matchValueRegex>
      <newValue>https://api.teste.com</newValue>
      <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwu = ResponseRewriter([XML_URL])
f = FakeFlow("https://api.exemplo.com/v1/x?a=1", body=b"")
rwu.request(f)
assert f.request.pretty_url.startswith("https://api.teste.com/v1/x"), \
    "got " + f.request.pretty_url
assert f.request.headers["host"] == "api.teste.com", \
    "the Host header must follow the new host, got " + f.request.headers["host"]

# a URL that does not match is untouched
f = FakeFlow("https://outro.com/v1", body=b"")
rwu.request(f)
assert f.request.pretty_url == "https://outro.com/v1"

# --- response status on the response side
XML_STATUS = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>11</ruleType>
      <newValue>204</newValue>
      <matchRequest>false</matchRequest><matchResponse>true</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rws = ResponseRewriter([XML_STATUS])
f = FakeFlow("https://x.com/", FakeResp())
rws.response(f)
assert f.response.status_code == 204

# and it must not fire on the request
f = FakeFlow("https://x.com/", FakeResp(), body=b"x")
rws.request(f)
assert f.request.get_text() == "x"

# --- a rule matching both sides fires on both
XML_BOTH = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules><rewriteRule>
      <active>true</active><ruleType>7</ruleType>
      <matchValue>xxx</matchValue><matchValueRegex>false</matchValueRegex>
      <newValue>yyy</newValue><replaceType>2</replaceType>
      <matchRequest>true</matchRequest><matchResponse>true</matchResponse>
    </rewriteRule></rules>
</rewriteSet></rewriteSet-array>"""
rwb = ResponseRewriter([XML_BOTH])
assert rwb.rules[0].scope == "both"
f = FakeFlow("https://x.com/", FakeResp(), body=b"xxx")
f.response.text = "xxx"
rwb.request(f)
rwb.response(f)
assert f.request.get_text() == "yyy", "got " + repr(f.request.get_text())
assert f.response.get_text() == "yyy", "got " + repr(f.response.get_text())

# --- the first matching rule wins
XML_TWO = """<rewriteSet-array><rewriteSet>
    <active>true</active><name>S</name>
    <hosts><locationPatterns/></hosts>
    <rules>
      <rewriteRule><active>true</active><ruleType>7</ruleType>
        <matchValue>aaa</matchValue><matchValueRegex>false</matchValueRegex>
        <newValue>first</newValue>
        <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
      </rewriteRule>
      <rewriteRule><active>true</active><ruleType>7</ruleType>
        <matchValue>aaa</matchValue><matchValueRegex>false</matchValueRegex>
        <newValue>second</newValue>
        <matchRequest>true</matchRequest><matchResponse>false</matchResponse>
      </rewriteRule>
    </rules>
</rewriteSet></rewriteSet-array>"""
rwt = ResponseRewriter([XML_TWO])
f = FakeFlow("https://x.com/", body=b"aaa")
rwt.request(f)
assert f.request.get_text() == "first", "got " + repr(f.request.get_text())

print("All response rewriter tests passed")
