import unittest
from analyze import analyze_pcap
import os

class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.test_pcap = "test.pcap"  # Create a test PCAP file
        
    def test_analyze_pcap(self):
        if os.path.exists(self.test_pcap):
            results = analyze_pcap(self.test_pcap)
            self.assertIn('total_packets', results)
            self.assertIn('ip_sources', results)
            self.assertIn('ip_destinations', results)

if __name__ == '__main__':
    unittest.main()
