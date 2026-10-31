import unittest

from backend.analyzer import CustomInstructions, SUPPORTED_CWES, UnsupportedCWEError, analyze


class AnalyzerRuleTests(unittest.TestCase):
    def test_catalog_cwes_are_supported(self):
        self.assertEqual(SUPPORTED_CWES, {78, 79, 89, 352, 787, 862, 918})

    def test_command_injection_requires_shell_sink(self):
        vulnerable = analyze(
            'import os\nvalue = request.args.get("cmd")\nos.system(value)', [78]
        )
        safe = analyze(
            'import subprocess\nvalue = request.args.get("cmd")\n'
            'subprocess.run(["echo", value], shell=False)', [78]
        )
        self.assertEqual([item.cwe_id for item in vulnerable.findings], [78])
        self.assertEqual(safe.findings, ())

    def test_xss_sink_and_escape_sanitizer(self):
        vulnerable = analyze(
            'value = request.args.get("name")\nmark_safe(value)', [79]
        )
        safe = analyze(
            'import html\nvalue = request.args.get("name")\n'
            'escaped = html.escape(value)\nmark_safe(escaped)', [79]
        )
        self.assertEqual([item.cwe_id for item in vulnerable.findings], [79])
        self.assertEqual(safe.findings, ())

    def test_sql_injection_and_parameterized_query(self):
        vulnerable = analyze(
            'value = request.args.get("name")\n'
            'cursor.execute("SELECT " + value)', [89]
        )
        parameterized = analyze(
            'value = request.args.get("name")\n'
            'cursor.execute("SELECT * FROM users WHERE name = %s", (value,))', [89]
        )
        self.assertEqual([item.cwe_id for item in vulnerable.findings], [89])
        self.assertEqual(parameterized.findings, ())

    def test_ssrf_tracks_outbound_url(self):
        result = analyze(
            'import requests\nurl = request.args.get("url")\nrequests.get(url)', [918]
        )
        self.assertEqual([item.cwe_id for item in result.findings], [918])

    def test_import_aliases_are_resolved_for_sources_and_sinks(self):
        result = analyze(
            'from flask import request as req\nimport os as operating_system\n'
            'value = req.args.get("cmd")\noperating_system.system(value)', [78]
        )
        self.assertEqual([item.cwe_id for item in result.findings], [78])
        self.assertEqual(result.sources[0].expression, "request.args")

    def test_custom_sinks_and_tracked_variables_are_separate(self):
        instructions = CustomInstructions(
            sinks=frozenset({"internal_sink"}),
            tracked_variables=frozenset({"tracked"}),
        )
        result = analyze(
            'tracked = request.args.get("x")\ninternal_sink(tracked)',
            [89],
            instructions,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.custom_findings), 1)
        self.assertEqual(len(result.custom_observations), 1)

    def test_custom_rules_work_independently_of_selected_cwe_flows(self):
        result = analyze(
            'value = request.args.get("x")\ninternal_sink(value)',
            [352],
            CustomInstructions(sinks=frozenset({"internal_sink"})),
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.custom_findings), 1)

    def test_cwe_787_tracks_low_level_write_size(self):
        vulnerable = analyze(
            'import ctypes\nsize = request.args.get("size")\n'
            'ctypes.memmove(dst, src, int(size))', [787]
        )
        safe_source_position = analyze(
            'import ctypes\ndata = request.args.get("data")\n'
            'ctypes.memmove(dst, data, 8)', [787]
        )
        self.assertEqual([item.cwe_id for item in vulnerable.findings], [787])
        self.assertEqual(safe_source_position.findings, ())

    def test_route_heuristics_report_csrf_and_auth_candidates(self):
        source = (
            'from flask import Flask\napp = Flask(__name__)\n'
            '@app.route("/update", methods=["POST"])\n'
            'def update(): pass\n'
        )
        findings = analyze(source, [352, 862]).findings
        self.assertEqual({item.cwe_id for item in findings}, {352, 862})
        self.assertTrue(all(item.finding_kind == "route_heuristic" for item in findings))
        self.assertTrue(all(item.source_line_number is None for item in findings))
        self.assertTrue(all(item.sink_line_number is None for item in findings))
        self.assertTrue(all(item.location_line_number is not None for item in findings))

    def test_route_guards_suppress_route_candidates(self):
        source = (
            'from flask import Flask\napp = Flask(__name__)\n'
            '@app.post("/update")\n@csrf_protect\n@login_required\n'
            'def update(): pass\n'
        )
        self.assertEqual(analyze(source, [352, 862]).findings, ())

    def test_django_middleware_and_body_guard_are_recognized(self):
        source = (
            'MIDDLEWARE = ["django.middleware.csrf.CsrfViewMiddleware"]\n'
            'from django.views.decorators.http import require_POST as post_only\n'
            '@post_only\ndef update(request):\n'
            '    if request.user.is_authenticated: return "ok"\n'
            '    return "denied"\n'
        )
        self.assertEqual(analyze(source, [352, 862]).findings, ())

    def test_multi_cwe_scan_and_limit(self):
        source = (
            'import os\nvalue = request.args.get("x")\n'
            'os.system(value)\ncursor.execute("SELECT " + value)\n'
        )
        result = analyze(source, [78, 89])
        self.assertEqual({item.cwe_id for item in result.findings}, {78, 89})
        with self.assertRaises(ValueError):
            analyze("pass", [78, 79, 89, 352, 918])
        with self.assertRaises(UnsupportedCWEError):
            analyze("pass", [999])


if __name__ == "__main__":
    unittest.main()
