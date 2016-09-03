# -*- coding: utf-8 -*-

from .context import keepasshttp

import unittest

class BasicTestSuite(unittest.TestCase):
    """Basic test cases."""

    def setUp(self):
        self.store = sample.KeePassHTTP("test_passphrase", 'test')

    def test_associate_ok(self):
        r = self.store.test_associate()
        self.assertTrue(r)

    def test_create_login(self):
        r = self.store.set_login("https://www.python.org","test_user","test_password")
        self.assertTrue(r)

    def test_generate_password(self):
        r = self.store.generate_password()
        self.assertEqual(1, len(r))

    def test_update_login(self):
        r = self.store.get_logins("https://www.python.org")
        self.assertEqual(1, len(r))
        r = self.store.set_login("https://www.python.org","new_user","new_password",r[0]['Uuid'])
        self.assertTrue(r)

    def test_get_logins_empty(self):
        r = self.store.get_logins("www.doesnotexist.com")
        self.assertEqual(0, len(r))

    def test_get_logins_match_title(self):
        r = self.store.get_logins("www.python.org")
        self.assertEqual(1, len(r))

    def test_get_logins_match_host_urlfield(self):
        r = self.store.get_logins("www.python.org")
        self.assertEqual(1, len(r))

    def test_get_logins_match_exact_urlfield(self):
        r = self.store.get_logins("https://www.python.org")
        self.assertEqual(1, len(r))

    def test_get_logins_match_exact_urlfield_subpath(self):
        r = self.store.get_logins("https://www.python.org/doc/")
        self.assertEqual(1, len(r))

if __name__ == '__main__':
    unittest.main()
