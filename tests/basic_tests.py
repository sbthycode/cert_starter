import unittest
import sys
sys.path.insert(0, 'D:\Semester8\CS431\cert_starter')
from solution.certChainCheck import x509_cert_chain_check

class TestBasicDomains(unittest.TestCase):

    def test_google(self):
        self.assertEqual(x509_cert_chain_check("google.com"), True, 
        "google.com has valid cert.")
    
    def test_facebook(self):
        self.assertEqual(x509_cert_chain_check("www.facebook.com"), True, 
        "www.facebook.com has valid cert.")

    def test_expired(self):
        self.assertEqual(x509_cert_chain_check("expired.badssl.com"), False, 
        "expired.badssl.com has an invalid cert.")

    def test_wrong_host(self):
        self.assertEqual(x509_cert_chain_check("wrong.host.badssl.com"), False, 
        "wrong.host.badssl.com has an invalid cert.")

if __name__ == '__main__':
    unittest.main()
