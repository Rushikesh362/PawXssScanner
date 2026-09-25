"""Offline tests for PawXssScanner's pure logic.

No network. Context detection, URL helpers and payload selection are all
testable without sending a single request.
"""
import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pawxss import (_classify_at, build_adaptive, charset_probe,
                    encode_double_url, encode_entities, encode_url,
                    expand_variants, find_contexts, get_params,
                    load_payloads, mutate_breaks, mutate_case,
                    mutate_comments, mutate_events, mutate_nested,
                    mutate_quotes, payloads_for, probe_events, probe_fillers,
                    probe_tags, set_param)


class UrlTests(unittest.TestCase):
    def test_params(self):
        self.assertEqual(get_params("https://t.com/s?q=1&page=2"), {"q": "1", "page": "2"})

    def test_set_param_keeps_others(self):
        out = set_param("https://t.com/s?q=1&page=2", "q", "X")
        self.assertIn("q=X", out)
        self.assertIn("page=2", out)

    def test_set_param_adds_missing(self):
        self.assertIn("q=X", set_param("https://t.com/s", "q", "X"))


class ContextTests(unittest.TestCase):
    def test_html(self):
        body = "<html><p>hello MARKER bye</p></html>"
        self.assertEqual(find_contexts(body, "MARKER"), ["html"])

    def test_double_quoted_attribute(self):
        body = '<input type="text" value="MARKER">'
        self.assertEqual(find_contexts(body, "MARKER"), ["attribute"])

    def test_single_quoted_attribute(self):
        body = "<input value='MARKER'>"
        self.assertEqual(find_contexts(body, "MARKER"), ["attribute-single"])

    def test_script(self):
        body = "<script>var x = 'MARKER';</script>"
        self.assertEqual(find_contexts(body, "MARKER"), ["script"])

    def test_comment(self):
        body = "<!-- MARKER -->"
        self.assertEqual(find_contexts(body, "MARKER"), ["comment"])

    def test_no_reflection(self):
        self.assertEqual(find_contexts("<p>nothing here</p>", "MARKER"), [])

    def test_multiple_reflections(self):
        body = "<p>MARKER</p><!-- MARKER -->"
        self.assertEqual(find_contexts(body, "MARKER"), ["html", "comment"])


class PayloadTests(unittest.TestCase):
    def test_context_payloads_come_first(self):
        pool = payloads_for("attribute", ["<custom>"])
        self.assertLess(pool.index('"><svg/onload=alert(1)>'), pool.index("<custom>"))

    def test_no_duplicates(self):
        pool = payloads_for("html", ["<svg/onload=alert(1)>"])
        self.assertEqual(len(pool), len(set(pool)))

    def test_wordlist_loads(self):
        items = load_payloads("payloads.txt")
        self.assertGreater(len(items), 20)


class BypassTests(unittest.TestCase):
    def test_case_mutation_changes_shape(self):
        out = mutate_case("<svg/onload=alert(1)>")
        self.assertNotEqual(out, "<svg/onload=alert(1)>")
        self.assertEqual(out.lower(), "<svg/onload=alert(1)>")

    def test_comment_mutation_breaks_tag(self):
        self.assertEqual(mutate_comments("<svg/onload=alert(1)>"),
                         "<svg/**/onload=alert(1)>")

    def test_break_mutation(self):
        self.assertEqual(mutate_breaks("<svg/onload=alert(1)>"),
                         "<svg%0aonload=alert(1)>")

    def test_url_encoding_roundtrip_markers(self):
        self.assertIn("%3C", encode_url("<svg>"))
        self.assertNotIn("<", encode_url("<svg>"))
        self.assertIn("%253C", encode_double_url("<"))
        self.assertIn("&lt;", encode_entities("<"))

    def test_expand_caps_variants(self):
        variants = expand_variants("<svg/onload=alert(1)>", set(), 3)
        self.assertEqual(variants[0], "<svg/onload=alert(1)>")
        self.assertLessEqual(len(variants), 3)

    def test_expand_uses_only_viable_encodings(self):
        full = expand_variants("<svg>", {"url"}, 0)
        encoded = [v for v in full if "%3C" in v]
        self.assertTrue(encoded)
        plain = expand_variants("<svg>", set(), 0)
        self.assertFalse([v for v in plain if "%3C" in v or "&lt;" in v])

    def test_expand_deterministic(self):
        first = expand_variants("<svg/onload=alert(1)>", {"url", "entity"}, 6)
        second = expand_variants("<svg/onload=alert(1)>", {"url", "entity"}, 6)
        self.assertEqual(first, second)

    def test_event_mutation_swaps_handler(self):
        self.assertEqual(mutate_events("<svg/onload=alert(1)>"),
                         "<svg/onerror=alert(1)>")
        self.assertEqual(mutate_events("<svg/onload=prompt(1)>"),
                         "<svg/onerror=prompt(1)>")

    def test_quote_mutation_swaps_style(self):
        self.assertEqual(mutate_quotes('"><svg/onload=alert(1)>'),
                         "'><svg/onload=alert(1)>")

    def test_new_mutations_appear_in_expansion(self):
        variants = expand_variants("<svg/onload=alert(1)>", set(), 0)
        self.assertIn("<svg/onerror=alert(1)>", variants)
        quoted = expand_variants('"><svg/onload=alert(1)>', set(), 0)
        self.assertIn("'><svg/onload=alert(1)>", quoted)

    def test_nested_mutation(self):
        self.assertEqual(mutate_nested("<script>alert(1)</script>"),
                         "<scr<script>ipt>alert(1)</script>")
        self.assertIn("<scr<script>ipt>alert(1)</script>",
                      expand_variants("<script>alert(1)</script>", set(), 0))

    def test_pool_has_depth(self):
        items = load_payloads("payloads.txt")
        self.assertGreater(len(items), 2500)


class _FakeResp:
    def __init__(self, status, text):
        self.status = status
        self.text = text
        self.headers = {}


def _echo_fetch_factory(blocked=()):
    """Fake fetch: reflects the value verbatim unless it holds a blocked word."""
    def fetch(url):
        import urllib.parse
        query = urllib.parse.urlparse(url).query
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        value = pairs[-1][1] if pairs else ""
        if any(word in value for word in blocked):
            return _FakeResp(200, "<p>filtered</p>")
        return _FakeResp(200, f"<p>you said: {value}</p>")
    return fetch


class AdaptiveTests(unittest.TestCase):
    def test_builder_uses_discovered_components(self):
        pool = build_adaptive("html", ["/"], ["d3v"], ["onfocus"], 10)
        self.assertEqual(pool[0], "<d3v/onfocus=alert(1)>")
        self.assertLessEqual(len(pool), 10)

    def test_builder_respects_limit(self):
        pool = build_adaptive("html", [" ", "/"], ["svg", "a"],
                              ["onload", "onclick"], 25)
        self.assertEqual(len(pool), 25)

    def test_builder_attribute_context(self):
        pool = build_adaptive("attribute", [" "], ["svg"], ["onload"], 5)
        self.assertTrue(pool[0].startswith('"'))

    def test_builder_script_context(self):
        pool = build_adaptive("script", [" "], ["svg"], ["onload"], 10)
        self.assertTrue(any("//" in p for p in pool))

    def test_filler_probe_finds_passing_separator(self):
        fetch = _echo_fetch_factory(blocked=[" "])
        viable = probe_fillers(fetch, "https://t.com/?q=1", "q")
        self.assertNotIn(" ", viable)
        self.assertIn("/", viable)

    def test_tag_probe_skips_filtered_names(self):
        fetch = _echo_fetch_factory(blocked=["svg", "script"])
        viable = probe_tags(fetch, "https://t.com/?q=1", "q")
        self.assertNotIn("svg", viable)
        self.assertIn("d3v", viable)

    def test_event_probe_drops_canary(self):
        fetch = _echo_fetch_factory(blocked=[])
        viable = probe_events(fetch, "https://t.com/?q=1", "q")
        self.assertNotIn("onxxx", viable)
        self.assertIn("onload", viable)

    def test_event_probe_inside_viable_tag(self):
        # svg blocked: events must still be discoverable via a passing tag.
        fetch = _echo_fetch_factory(blocked=["svg"])
        self.assertEqual(probe_events(fetch, "https://t.com/?q=1", "q"), [])
        chained = probe_events(fetch, "https://t.com/?q=1", "q", tag="d3v")
        self.assertIn("onload", chained)
        self.assertNotIn("onxxx", chained)

    def test_tag_probe_avoids_spaces(self):
        # A space-blocking filter must not hide passing tag names.
        fetch = _echo_fetch_factory(blocked=[" "])
        viable = probe_tags(fetch, "https://t.com/?q=1", "q")
        self.assertIn("d3v", viable)

    def test_block_status_excludes(self):
        def fetch(url):
            return _FakeResp(403, "blocked")
        self.assertEqual(probe_fillers(fetch, "https://t.com/?q=1", "q"), [])
        self.assertEqual(probe_tags(fetch, "https://t.com/?q=1", "q"), [])
        self.assertEqual(probe_events(fetch, "https://t.com/?q=1", "q"), [])

    def test_tuple_fetch_unwrapped(self):
        # Scanner.fetch returns (response, error); probes must cope.
        inner = _echo_fetch_factory(blocked=[])
        def fetch(url):
            return inner(url), None
        self.assertIn("/", probe_fillers(fetch, "https://t.com/?q=1", "q"))
        self.assertIn("svg", probe_tags(fetch, "https://t.com/?q=1", "q"))
        self.assertIn("onload", probe_events(fetch, "https://t.com/?q=1", "q"))

    def test_filler_probe_matches_decoded_reflection(self):
        # %09 must be detected via the decoded tab, not the literal "%09".
        fetch = _echo_fetch_factory(blocked=[])
        viable = probe_fillers(fetch, "https://t.com/?q=1", "q")
        self.assertIn(" ", viable)
        self.assertIn("%09", viable)
        self.assertIn("/", viable)

    def test_charset_probe_finds_single_decode(self):
        # Stub decodes once, like a normal server: only "url" is viable.
        fetch = _echo_fetch_factory(blocked=[])
        self.assertEqual(charset_probe(fetch, "https://t.com/?q=1", "q"), {"url"})


if __name__ == "__main__":
    unittest.main()
