import unittest

from extract_text import read_two_byte_offset, BinaryStream, read_literal_length, read_long_compression_offset

class TestDecompression(unittest.TestCase):
    def test_two_byte_offset(self):
        bytez = b'\xF0\x07'
        result, opcode = read_two_byte_offset(BinaryStream(bytez))
        self.assertEqual(result, 508)
        self.assertEqual(opcode, 0)
    
    def test_read_literal_length(self):
        bytez = b'\x05'
        lit_length, _ = read_literal_length(BinaryStream(bytez))
        self.assertEqual(lit_length, 0x08)

    def test_read_long_compression_offset(self):
        bytez = b'\xDD'
        self.assertEqual(read_long_compression_offset(BinaryStream(bytez)), 0xDD)

if __name__ == "__main__": unittest.main()