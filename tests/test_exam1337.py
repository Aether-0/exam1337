import unittest
import exam1337

class DetectorTests(unittest.TestCase):
    def test_demo(self):
        self.assertTrue(exam1337.analyze_http(exam1337.DEMO))

    def test_no_secrets_in_report(self):
        raw = "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npassword=topsecret"
        self.assertNotIn("topsecret", str(exam1337.analyze_http(raw)))

    def test_clean_request(self):
        self.assertEqual(exam1337.analyze_http("GET / HTTP/1.1\r\nHost: lab\r\n\r\n"), [])

if __name__ == "__main__":
    unittest.main()
