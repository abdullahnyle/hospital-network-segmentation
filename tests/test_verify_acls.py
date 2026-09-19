import contextlib
import io
import unittest
from unittest.mock import patch

import verify_acls as checker


class ACLTests(unittest.TestCase):
    def test_first_match_and_implicit_deny(self):
        rules = checker.parse_acl_lines('''access-list 140 deny ip host 192.168.20.25 any
access-list 140 permit ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255''')
        self.assertEqual(checker.evaluate_acl(rules, '140', '192.168.20.25', '192.168.10.25'), 'deny')
        self.assertEqual(checker.evaluate_acl(rules, '140', '192.168.20.26', '192.168.10.25'), 'permit')
        self.assertEqual(checker.evaluate_acl(rules, '140', '192.168.20.26', '198.51.100.25'), 'deny')

    def test_noncontiguous_wildcard(self):
        rules = checker.parse_acl_lines('access-list 1 permit ip 10.0.0.0 0.0.5.255 any')
        self.assertEqual(checker.evaluate_acl(rules, '1', '10.0.4.1', '192.0.2.1'), 'permit')
        self.assertEqual(checker.evaluate_acl(rules, '1', '10.0.2.1', '192.0.2.1'), 'deny')

    def test_unsupported_syntax_fails(self):
        for line in ['access-list 140 permit tcp any any', 'access-list 140 permit ip any',
                     'access-list 140 permit ip any any log']:
            with self.subTest(line=line), self.assertRaises(ValueError):
                checker.parse_acl_lines(line)

    def run_config(self, config):
        original = checker.Path.read_text
        def read(path, *args, **kwargs):
            return config if path == checker.CONFIG_PATH else original(path, *args, **kwargs)
        with patch.object(checker.Path, 'read_text', read), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                checker.main()
        return result.exception.code

    def test_committed_policy_passes(self):
        self.assertEqual(self.run_config(checker.CONFIG_PATH.read_text()), 0)

    def test_early_permit_is_rejected(self):
        config = checker.CONFIG_PATH.read_text().replace('access-list 110 deny',
            'access-list 110 permit ip any any\naccess-list 110 deny', 1)
        self.assertEqual(self.run_config(config), 1)

    def test_wrong_interface_binding_is_rejected(self):
        config = checker.CONFIG_PATH.read_text().replace('ip access-group 140 in', 'ip access-group 130 in')
        self.assertEqual(self.run_config(config), 1)

    def test_missing_clinical_fallback_permit_is_rejected(self):
        config = checker.CONFIG_PATH.read_text().replace(
            'access-list 140 permit ip any any\n', ''
        )
        self.assertEqual(self.run_config(config), 1)


if __name__ == '__main__':
    unittest.main()
