import unittest

from src.protocol.messages import MessageError, build_line, parse_line


class TestBuildLine(unittest.TestCase):
    def test_step1_shape(self):
        self.assertEqual(build_line("STEP1", "alice", "bob", "7311"), "STEP1|alice|bob|7311")

    def test_single_field(self):
        self.assertEqual(build_line("STEP3", "ABCD"), "STEP3|ABCD")

    def test_no_fields(self):
        self.assertEqual(build_line("STEP7"), "STEP7")

    def test_field_with_spaces_and_symbols(self):
        self.assertEqual(build_line("STEP5", "NB 12x!"), "STEP5|NB 12x!")

    def test_reject_field_with_delim(self):
        with self.assertRaises(MessageError):
            build_line("STEP1", "alice", "bo|b")
        with self.assertRaises(MessageError):
            build_line("STEP1", "")

    def test_reject_step_with_delim_or_empty(self):
        with self.assertRaises(MessageError):
            build_line("|STEP1", "a")
        with self.assertRaises(MessageError):
            build_line("", "a")

    def test_reject_non_ascii(self):
        with self.assertRaises(MessageError):
            build_line("STEP1", "alïce")
        with self.assertRaises(MessageError):
            build_line("STEP1", "\n")

    def test_reject_non_str(self):
        with self.assertRaises(MessageError):
            build_line("STEP1", 42)


class TestParseLine(unittest.TestCase):
    def test_parse_step1(self):
        step, fields = parse_line("STEP1|alice|bob|7311")
        self.assertEqual(step, "STEP1")
        self.assertEqual(fields, ("alice", "bob", "7311"))

    def test_parse_no_fields(self):
        self.assertEqual(parse_line("STEP7"), ("STEP7", ()))

    def test_roundtrip_arbitrary_valid_args(self):
        cases = [
            ("STEP2", ("ks123", "alice", "bob", "7311")),
            ("STEP3", ("ks123", "alice")),
            ("STEP4", ("8263914",)),
            ("STEP5", ("8263914x",)),
        ]
        for step, fields in cases:
            self.assertEqual(parse_line(build_line(step, *fields)), (step, fields))

    def test_strips_line_endings(self):
        self.assertEqual(parse_line("STEP4|1000\n"), ("STEP4", ("1000",)))
        self.assertEqual(parse_line("STEP4|1000\r\n"), ("STEP4", ("1000",)))

    def test_reject_empty_step(self):
        with self.assertRaises(MessageError):
            parse_line("|field")

    def test_reject_empty_field(self):
        with self.assertRaises(MessageError):
            parse_line("STEP1|a||b")

    def test_reject_non_ascii_field(self):
        with self.assertRaises(MessageError):
            parse_line("STEP1|alïce")

    def test_reject_non_str(self):
        with self.assertRaises(MessageError):
            parse_line(b"STEP1|a")


if __name__ == "__main__":
    unittest.main()
