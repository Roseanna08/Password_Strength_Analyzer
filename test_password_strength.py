import unittest
from password_strength import check_strength, entropy, detect_patterns, crack_time

class TestPasswordStrength(unittest.TestCase):
    def test_empty_password_is_weak(self):
        result, reasons, flags, count = check_strength("")
        self.assertEqual(result, "WEAK")

class TestCheckStrength(unittest.TestCase):
    def test_empty_password_is_weak(self):
        result, reasons, flags, count = check_strength("")
        self.assertEqual(result, "WEAK")
        
    def test_all_lowercase_is_weak(self):
        result, reasons, flags, count = check_strength("apple")
        self.assertEqual(result, "WEAK")

    def test_medium_password(self):
        result, reasons, flags, count = check_strength("apple123")
        self.assertEqual(result, "MEDIUM")

    def test_strong_password(self):
        result, reasons, flags, count = check_strength("Tr0ub4dor&3xyz")
        self.assertEqual(result, "STRONG")

class TestDetectPattern(unittest.TestCase):
    def test_consecutive_letters(self):
        patterns=detect_patterns("asdf")
        self.assertEqual(patterns, ["Consecutive letters"])

    def test_consecutive_digits(self):
        patterns=detect_patterns("56789")
        self.assertEqual(patterns, ["Consecutive digits"])

    def test_year_used(self):
        patterns=detect_patterns("hi2027")
        self.assertEqual(patterns, ["Year used in password"])

    def test_repeated_charecters(self):
        patterns=detect_patterns("aaa")
        self.assertEqual(patterns, ["Repeated characters"])

    def test_repeated_block(self):
        patterns=detect_patterns("roseroserose")
        self.assertEqual(patterns, ["Repeated block"])

    def test_common_password(self):
        patterns=detect_patterns("welcomeadmin")
        self.assertEqual(patterns, ["Common password"])

class TestEntropy(unittest.TestCase):
    def test_empty_password_has_zero_entropy(self):
        self.assertEqual(entropy(""), 0)

    def test_apple123_entropy(self):
        self.assertAlmostEqual(entropy("apple123"), 41.4, places=1)

    def test_strong_password_entropy(self):
        self.assertAlmostEqual(entropy("Tr0ub4dor&3xyz"), 91.8, places=1)


class TestCrackTime(unittest.TestCase):
    def test_zero_entropy_is_instant(self):
        self.assertEqual(crack_time(0), "0.0 seconds")

    def test_medium_entropy_is_minutes(self):
        self.assertEqual(crack_time(entropy("apple123")), "47.0 minutes")

    def test_high_entropy_is_uncrackable(self):
        self.assertEqual(crack_time(100), "Centuries (uncrackable)")

if __name__ == "__main__":
    unittest.main()
