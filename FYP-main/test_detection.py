import unittest
import requests

class TestDetection(unittest.TestCase):
    def test_detect_attack(self):
        """Test detection of a network attack."""
        # Features indicating an attack
        data = {
            "PROTOCOL": "TCP",
            "TCP_FLAGS": "SYN",
        }

        # Send the request to the web application
        response = requests.post('http://127.0.0.1:5000/detect', json=data)
        result = response.json()

        # Check response status
        self.assertEqual(result["Status"], "Matched", "Expected matched status")

        # Ensure action and attack labels align with expected ones
        self.assertEqual(result["Action"], "Attack")
        self.assertEqual(result["Attack"], "DDoS")  # Or other valid label

    def test_detect_benign(self):
        """Test detection of benign traffic."""
        # Benign traffic features
        data = {
            "PROTOCOL": "UDP",
            "TCP_FLAGS": "",
        }

        response = requests.post('http://127.0.0.1:5000/detect', json=data)
        result = response.json()

        # Check response status
        self.assertEqual(result["Status"], "Matched", "Expected matched status")

        # Ensure action and attack labels align with expected ones
        self.assertEqual(result["Action"], "Benign")
        self.assertEqual(result["Attack"], "None")

    def test_invalid_data(self):
        """Handle malformed input gracefully."""
        data = {"PROTOCOL": "Unknown"}

        response = requests.post('http://127.0.0.1:5000/detect', json=data)
        self.assertEqual(response.status_code, 400)

    def test_specific_scenarios(self):
        """Test specific traffic patterns."""
        scenarios = [
            {"data": {"PROTOCOL": "TCP", "TCP_FLAGS": "ACK"}, "expected_action": "Benign", "expected_attack": "None"},
            {"data": {"PROTOCOL": "TCP", "TCP_FLAGS": "SYN-ACK"}, "expected_action": "Attack", "expected_attack": "DDoS"},
        ]

        for scenario in scenarios:
            response = requests.post('http://127.0.0.1:5000/detect', json=scenario["data"])
            result = response.json()

            # Check response status
            self.assertEqual(result["Status"], "Matched", "Expected matched status")

            # Ensure action and attack labels align with expected ones
            self.assertEqual(result["Action"], scenario["expected_action"])
            self.assertEqual(result["Attack"], scenario["expected_attack"])

if __name__ == '__main__':
    unittest.main()
