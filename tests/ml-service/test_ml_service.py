import unittest
import os
import sys

# Ensure ml-service root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml-service")))

from fastapi.testclient import TestClient
from main import app

class TestMLService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])

    def test_model_info(self):
        response = self.client.get("/model-info")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["algorithm"], "Isolation Forest")
        self.assertIn("request_rate_per_min", data["features"])

    def test_detect_normal_traffic(self):
        payload = {
            "event_id": "test_normal",
            "source_ip": "192.168.1.50",
            "target_endpoint": "/api/v1/home",
            "request_rate_per_min": 25.0,
            "failed_logins_last_10m": 0,
            "payload_size_kb": 12.0,
            "geo_deviation_score": 5.0,
            "unique_ports_scanned": 1,
            "error_rate_percent": 1.0
        }
        response = self.client.post("/detect", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("anomaly_score", data)
        self.assertIn(data["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_detect_brute_force_anomaly(self):
        payload = {
            "event_id": "test_brute_force",
            "source_ip": "198.51.100.99",
            "target_endpoint": "/api/v1/auth/login",
            "request_rate_per_min": 600.0,
            "failed_logins_last_10m": 35,
            "payload_size_kb": 5.0,
            "geo_deviation_score": 85.0,
            "unique_ports_scanned": 1,
            "error_rate_percent": 90.0
        }
        response = self.client.post("/detect", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["is_anomaly"])
        self.assertIn(data["severity"], ["HIGH", "CRITICAL"])
        self.assertTrue(any("failed login" in reason.lower() for reason in data["reasons"]))

if __name__ == "__main__":
    unittest.main()
