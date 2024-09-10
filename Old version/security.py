import unittest
from . import app

class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_csrf_protection(self):
        # Send POST request without CSRF token
        response = self.client.post('/some-secure-endpoint', data={'key': 'value'})
        self.assertEqual(response.status_code, 400)  # Expecting CSRF error

if __name__ == '__main__':
    unittest.main()
