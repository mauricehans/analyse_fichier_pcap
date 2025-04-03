import unittest
from app import app
import os
import json

class TestApp(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_upload_no_file(self):
        response = self.client.post('/upload')
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'No file part')

    def test_check_ip_no_ip(self):
        response = self.client.post('/check_ip', 
                                  json={})
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'No IP provided')

    def test_fetch_pcap(self):
        response = self.client.get('/fetch_pcap')
        data = json.loads(response.data)
        self.assertIn('success', data)

if __name__ == '__main__':
    unittest.main()
