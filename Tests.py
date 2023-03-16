import unittest

from API import DNSHeader


class TestDNSHeader(unittest.TestCase):
    def test_pack_unpack_dns_flags(self):
        flags_tuple = (True, 13, True, False, True, False, 2)
        packed_flags = DNSHeader.pack_dns_flags(flags_tuple)
        flags = DNSHeader.unpack_dns_flags(packed_flags)
        self.assertEqual(flags, flags_tuple)

    def test_questions_to_bytes(self):
        questions = [
            ('example.com', 1, 1),
            ('google.com', 2, 2),
            ('facebook.co.il', 1, 2)
        ]
        header = DNSHeader(identification=0x1234, flags=1, num_questions=len(questions), num_answers=0, num_authority_rr=0,
                           num_additional_rr=0, questions=questions)
        result = DNSHeader.from_bytes(header.pack())
        self.assertEqual(result[0], questions)

    def test_answers_to_bytes(self):
        questions = [
            ('example.com', 1, 1),
            ('google.com', 2, 2),
            ('facebook.co.il', 1, 2)
        ]
        answers = [
            ('example.com', 1, 1, 64, 2, b'\x01\x01'),
            ('google.com', 2, 2, 64, 2, b'\x02\x02'),
            ('facebook.co.il', 1, 64, 3, 2, b'\x03\x03')
        ]
        header = DNSHeader(identification=0x1234, flags=1, num_questions=len(questions), num_answers=len(answers),
                           num_authority_rr=0, questions=questions,
                           num_additional_rr=0, answers=answers)
        result = DNSHeader.from_bytes(header.pack())
        self.assertEqual(result[1], answers)
