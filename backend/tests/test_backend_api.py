import importlib.util
import unittest


FLASK_AVAILABLE = importlib.util.find_spec("flask") is not None


@unittest.skipUnless(FLASK_AVAILABLE, "install backend/requirements.txt to run Flask API tests")
class BackendApiTests(unittest.TestCase):
    def setUp(self):
        from backend.app import create_app

        class Repository:
            def __init__(self):
                self.telemetry = []
                self.unavailable = False

            def list_cwes(self):
                if self.unavailable:
                    from backend.app.database import DatabaseUnavailable

                    raise DatabaseUnavailable("offline")
                return [{"cwe_id": cwe_id, "name": f"CWE-{cwe_id}"} for cwe_id in (78, 79, 89, 352, 787, 862, 918)]

            def record_scan(self, **metadata):
                if self.unavailable:
                    from backend.app.database import DatabaseUnavailable

                    raise DatabaseUnavailable("offline")
                self.telemetry.append(metadata)

        self.repository = Repository()
        self.app = create_app({"TESTING": True}, repository=self.repository)
        self.client = self.app.test_client()

    def test_health_and_seven_cwe_catalog(self):
        self.assertEqual(self.client.get("/health").json, {"status": "ok"})
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn(b"Python security scanner", home.data)
        home.close()
        for asset in ("app.js", "styles.css", "monaco-worker.js"):
            response = self.client.get(f"/assets/{asset}")
            self.assertEqual(response.status_code, 200)
            response.close()
        response = self.client.get("/api/cwes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["cwe_id"] for row in response.json["cwes"]], [78, 79, 89, 352, 787, 862, 918])

    def test_scan_returns_separate_custom_results_and_metadata_only(self):
        response = self.client.post(
            "/api/scan",
            json={
                "source_code": 'value = request.args.get("x")\ninternal_sink(value)',
                "cwe_ids": [89],
                "custom_instructions": {
                    "sinks": ["internal_sink"],
                    "tracked_variables": ["value"],
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["custom_findings"]), 1)
        self.assertEqual(len(response.json["custom_observations"]), 1)
        self.assertEqual(self.repository.telemetry[0]["selected_cwe_ids"], (89,))
        self.assertNotIn("source_code", self.repository.telemetry[0])

    def test_scan_continues_when_telemetry_database_is_unavailable(self):
        self.repository.unavailable = True
        with self.assertLogs("backend.app.routes", level="ERROR"):
            response = self.client.post("/api/scan", json={"source_code": "pass", "cwe_ids": [89]})
            catalog = self.client.get("/api/cwes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(catalog.status_code, 503)
        response.close()
        catalog.close()

    def test_invalid_python_and_custom_rules_return_json_errors(self):
        invalid_python = self.client.post("/api/scan", json={"source_code": "def (", "cwe_ids": [89]})
        invalid_rules = self.client.post(
            "/api/scan",
            json={"source_code": "pass", "custom_instructions": {"tracked_variables": ["bad-name"]}},
        )
        self.assertEqual(invalid_python.status_code, 422)
        self.assertEqual(invalid_python.json["error"]["code"], "invalid_python")
        self.assertEqual(invalid_rules.status_code, 400)
        self.assertEqual(invalid_rules.json["error"]["code"], "invalid_custom_instructions")


if __name__ == "__main__":
    unittest.main()
