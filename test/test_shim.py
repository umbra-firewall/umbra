#!/usr/bin/python

import sys
import httplib2
import unittest


url = None


class TestPageBlocking(unittest.TestCase):
    def setUp(self):
        pass

    def assert_is_blocked(self, body):
        self.assertTrue(is_blocked(body), "Page not blocked")

    def assert_is_not_blocked(self, body):
        self.assertFalse(is_blocked(body), "Page is blocked")

    def test_normal(self):
        h = httplib2.Http()
        (resp, body) = h.request(url)
        self.assert_is_not_blocked(body)

    def test_big_header_field(self):
        h = httplib2.Http()
        (resp, body) = h.request(url, headers={'X-' + 200 * 'A': 'value'})
        self.assert_is_blocked(body)

    def test_big_header_value(self):
        h = httplib2.Http()
        (resp, body) = h.request(url, headers={'X-test-header': 200*'A'})
        self.assert_is_blocked(body)


def is_blocked(body):
    return '<title>Action Not Allowed</title>' in body


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage: %s URL' % sys.argv[0]
        sys.exit(1)
    url = sys.argv[1]
    unittest.main(argv=[sys.argv[0]])
