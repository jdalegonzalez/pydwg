#! python
import argparse
import platform
import json
import logging
import io
import ezdxf

from ezdxf.entities import DXFEntity
from ezdxf.entities import Text
from ezdxf.entities import MText

from struct import *

import libredwg.LibreDWG

class BinaryStream:
    def __init__(self, base_stream):
        if type(base_stream) == bytes or type(base_stream) == bytearray:
            self.base_stream = io.BytesIO(base_stream)
        else:
            self.base_stream = base_stream        
    def readByte(self):
        return self.base_stream.read(1)

    def readByteNum(self):
        if (byte := self.base_stream.read(1)): return int(byte[0])
        return None

    def readBytes(self, length):
        return self.base_stream.read(length)

    def readChar(self):
        return self.unpack('b')

    def readUChar(self):
        return self.unpack('B')

    def readBool(self):
        return self.unpack('?')

    def readInt16(self):
        return self.unpack('h', 2)

    def readUInt16(self):
        return self.unpack('H', 2)

    def readInt32(self):
        return self.unpack('i', 4)

    def readUInt32(self):
        return self.unpack('I', 4)

    def readInt64(self):
        return self.unpack('q', 8)

    def readUInt64(self):
        return self.unpack('Q', 8)

    def readFloat(self):
        return self.unpack('f', 4)

    def readDouble(self):
        return self.unpack('d', 8)

    def readStringBytes(self, length):
        if (bytez := self.readBytes(length)):
            return bytez.decode('utf-8')
        return None
    
    def readString(self):
        if (length := self.readUInt16()):
            return self.unpack(str(length) + 's', length)
        return None
    
    def unpack(self, fmt, length = 1):
        if (bytez := self.readBytes(length)):
            return unpack(fmt, bytez)[0]
        return None

class r2004_DataHeader():
    def __init__(self):
        self.section_page_type = None
        self.section_number = None
        self.data_size = None
        self.page_size = None
        self.start_offset = None
        self.header_checksum = None
        self.data_checksum = None

    def read(self, f: io.BytesIO, address):
        f.seek(address)
        mask = 0x4164536b ^ address
        stream = BinaryStream(f)
        self.section_page_type  = stream.readInt32() ^ mask
        self.section_number     = stream.readInt32() ^ mask
        self.data_size          = stream.readInt32() ^ mask
        self.page_size          = stream.readInt32() ^ mask
        self.start_offset       = stream.readInt32() ^ mask
        self.header_checksum    = stream.readInt32() ^ mask
        self.data_checksum      = stream.readInt32() ^ mask
        log("unknown", stream.readInt32() ^ mask)

    def __repr__(self):
        return (
            "{"
            f'page_type: {self.section_page_type:#04x}, number: {self.section_number}, '
            f'data size: {self.data_size}, page size: {self.page_size}, offset: {self.start_offset}'
            "}"
        )

    def __str__(self):
        return (
            "{"
            f'page_type: {self.section_page_type:#04x}, number: {self.section_number}, '
            f'data size: {self.data_size}, page size: {self.page_size}, offset: {self.start_offset}'
            "}"
        )

class r2004_PageInfo():
    def __init__(self):
        self.number = 0
        self.size = 0
        self.start_offset = 0
    def __repr__(self):
        return (
            "{"
            f'number: {self.number}, number: {self.size}, '
            f'start offset: {self.start_offset:#04x}'
            "}"
        )

    def __str__(self):
        return (
            "{"
            f'number: {self.number}, number: {self.size}, '
            f'start offset: {self.start_offset:#04x}'
            "}"
        )

class r2004_PageDescription():
    def __init__(self, address: int = 0):
        self.address = address
        self.size = 0
        self.page_count = 0
        self.max_decompressed_size = 0
        self.compressed = 0
        self.section_id = 0
        self.encrypted = 0
        self.name = ""
        self.pages = []

    def read(self, stream:BinaryStream):
        self.size              = log('size_of_section',   stream.readInt64())
        self.page_count        = log('pages',             stream.readInt32())
        self.decompressed_size = log('decompressed_size', stream.readInt32(), True)
        _                      = log('unknown',           stream.readInt32())
        self.compressed        = log('compressed',        stream.readInt32())
        self.section_id        = log('section Id',        stream.readInt32())
        self.encrypted         = log('encrypted',         stream.readInt32())
        b = stream.readBytes(64)
        print(hex_dump_bytes(b, chars=True))
        self.name              = log('name',              b.decode('ascii'))
        for _ in range(self.page_count):
            page_info = r2004_PageInfo()
            page_info.number = stream.readInt32()
            page_info.size = stream.readInt32()
            page_info.start_offset = stream.readInt64()
            self.pages.append(page_info)

    def __repr__(self):
        return (
            "{"
            f'address: {self.address:#04x} name: "{self.name}", size: {self.size}, compressed: {self.compressed}, encrypted: {self.encrypted}'
            "}"
        )

    def __str__(self):
        return (
            "{"
            f'address: {self.address:#04x} name: "{self.name}", size: {self.size}, compressed: {self.compressed}, encrypted: {self.encrypted}'
            "}"
        )


class r2004_DataSectionMapEntry():
    def __init__(self, page_number: int = None, size: int = None, parent: int = None, left: int = None, right: int = None):
        self.page_number = page_number
        self.size = size
        self.parent = parent
        self.left = left
        self.right = right

class r2004_SystemSectionMapEntry():
    def __init__(self, page_number: int = None, address: int = None, size: int = None, parent: int = None, left: int = None, right: int = None):
        self.address = address
        self.page_number = page_number
        self.size = size
        self.parent = parent
        self.left = left
        self.right = right

    def __repr__(self):
        return "{"f'page_number: {self.page_number}, address: {self.address}, size: {self.size}'"}"

    def __str__(self):
        return "{"f'page_number: {self.page_number}, address: {self.address}, size: {self.size}'"}"

class r2004_Header():
    def __init__(self):
        self.version = None
        self.tag = None
        self.preview_address = None
        self.acad_version = None
        self.acad_release = None
        self.code_page = None
        self.encrypt_data = None
        self.encrypt_properties = None
        self.sign_data = None
        self.add_timestamp = None
        self.summary_address = None
        self.vbaproject_address = None
        self.file_id = None
        self.root_tree_node_gap = None
        self.lower_left_node_gap = None
        self.lower_right_node_gap = None
        self.last_section_page_id = None
        self.last_section_page_end_address = None
        self.second_header_address = None
        self.num_gaps = None
        self.num_sections = None
        self.section_map_id = None
        self.section_map_address = None
        self.section_info_id = None
        self.section_array_size = None
        self.gap_array_size = None
        self.crc32 = None
        self.system_sections_map: list[r2004_SystemSectionMapEntry] = None
        self.data_sections_map: list[r2004_DataSectionMapEntry] = None

    def __repr__(self):
        return "{"f'version: {self.version}, acad_version: {self.acad_version}, file_id: {self.file_id}'"}"

    def __str__(self):
        return "{"f'version: {self.version}, acad_version: {self.acad_version}, file_id: {self.file_id}'"}"

    def get_system_map_entry(self, id):
        for entry in self.system_sections_map:
            if entry.page_number == id: return entry
        return None
    def get_data_entry(self): 
        return self.get_system_map_entry(self.section_info_id)
    
def get_arguments():
    parser = argparse.ArgumentParser(
        description="Extracts the text from a .dwg file.  You need to have the ODA File Converted installed."
    )
    parser.add_argument(
        'filename',
        help="The path to the .dwg file to process.",
    )
    parser.add_argument(
        "-j", "--json",
        help="Print json results to standard out rather than plain text",
        dest="print_json",
        default=False,
        action='store_true'
    )
    parser.add_argument(
        '--no-location',
        help="Don't print out the coordinates of the text",
        dest="no_location",
        default=False,
        action='store_true'
    )
    parser.add_argument(
        '--one-line',
        help="If not printing json, print out as one long line.",
        dest="one_line",
        default=False,
        action='store_true'
    )
    parser.add_argument(
        '-l', '--log_level',
        help="The python logging level for output",
        dest='log_level',
        default="WARNING"
    )
    return parser.parse_args()

def is_text_entity(entity:DXFEntity) -> bool:
    return type(entity) == Text or type(entity) == MText

def get_text_segments(filename):
    if filename.endswith(".dwg"):
        from ezdxf.addons import odafc
        # HACK ALERT.  At least right now, the ezdxf plugin that reads dwg files
        # always fails on a mac because of ignorable stderr output that Apple spits
        # out that doesn't seem suppressable.  We're monkey patching the library
        # to work-around the issue.  Frankly, I think the code shouldn't care about
        # stderr and should always look at return code but what do I know.
        # 2025-01-22 14:05:17.579 ODAFileConverter[82652:39017271] +[IMKClient subclass]: chose IMKClient_Modern
        # 2025-01-22 14:05:17.579 ODAFileConverter[82652:39017271] +[IMKInputSession subclass]: chose IMKInputSession_Modern
        if platform.system() == "Darwin":
            def _darwin_failed(system: str, returncode: int, stderr: str) -> bool:
                return returncode != 0
            odafc._odafc_failed = _darwin_failed
        if platform.system() == "Windows":
            # ezdxf.addons.odafc.win_exec_path = <WHEREVER YOU PUT IT>
            pass
        else:
            # ezdxf.addons.odafc.unix_exec_path = <WHEREVER YOU PUT IT>
            pass
        if not ezdxf.addons.odafc.is_installed():
            logging.error(
"""
You need to install ODAFileConverter to process .dwg files.
Install application from https://www.opendesign.com/guestfiles/oda_file_converter
Then make sure it's in your path.  Or you can change this file to set:
ezdxf.addons.odafc.win_exec_path or ezdxf.addons.odafc.unix_exec_path
"""
            )
        doc = odafc.readfile(filename)
    else:
        doc = ezdxf.readfile(filename)
    text_pieces = []
    for entity in doc.entities:
        if is_text_entity(entity):
            loc = entity.dxf.insert
            coords = (loc.x, loc.y, loc.z)
            text_pieces.append({
                'text': entity.plain_text(),
                'location': coords
            })
    
    return text_pieces



def to_int(bytes):
    return int.from_bytes(bytes,"little")

def generate_magicnumber():
    ndx = 0
    size = 0x6c
    seed = 1
    value = bytearray(size)

    def bump(seed):
        seed *= 0x343fd
        seed += 0x269ec3
        return seed
    
    while ndx < size:
        seed = bump(seed)
        value[ndx] = ((seed >> 0x10) & 0xFF)
        ndx += 1

    return value

def fancy_hex_dump_bytes(bytez):
    hex_text = ""
    chars = ""
    text = ""
    for ndx, byte in enumerate(bytez):
        hex_text += f'{byte:#04x} '
        chars += ('.' if byte < 32 or byte >= 127 else chr(byte))
        if (ndx + 1) % 16 == 0:
            text += (hex_text + "    " + chars + "\n")
            hex_text = ""
            chars = ""
    
    if len(chars) > 0 and len(chars) < 16:
        hex_text = f'{hex_text:<80}'
        chars = f'{chars:<16}'
        text += (hex_text + "    " + chars + "\n")
    else:
        text += "\n"
    return text

def hex_dump_bytes(bytez, chars:bool = False):
    if type(bytez) != bytes and type(bytez) != bytearray: return f"{bytez:#04x}"
    res = ""
    for ndx, byte in enumerate(bytez):
        end = "\n" if ((ndx + 1) % 16) == 0 else " "
        ascii = byte > 32 and byte < 127
        res += ((f"{byte:#04x}" + end) if not chars or not ascii else "   " + chr(byte) + end)
    
    res = "\n" + res if "\n" in res else res
    return res

def decrypt_header(bytes):
    magic_number = generate_magicnumber()
    result = bytearray()
    for ndx, byte in enumerate(bytes): result.append(byte^magic_number[ndx])
    return result

def log(label, value=None, print_hex=False):
    if value == None:
        logging.debug(label)
        return
    
    v = value if not print_hex else hex_dump_bytes(value)
    logging.debug(f'{label}: {v}')
    return value

def read_literal_length(stream):
    total = 0
    byte = stream.readByteNum()
    opcode = 0x00
    length = 0
    if byte >= 0x01 and byte < 0x0F:
         length  = byte + 3
    elif byte == 0:
        total = 0x0F
        byte = stream.readByteNum()        
        while byte == 0:
            total += 0xFF
            byte = stream.readByteNum()
        length = total + byte + 3
    elif byte & 0xF0:
        opcode = byte
        length = 0
    
    return (length, opcode)

def read_two_byte_offset(stream):
    byte1 = stream.readByteNum()
    byte2 = stream.readByteNum()
    offset = ((byte1 >> 2)) | ((byte2 << 6))
    lit_length = (byte1 & 0x03)
    return (offset, lit_length)

def read_long_compression_offset(stream:BinaryStream):
    total = 0
    byte = stream.readByteNum()
    while not byte:
        total += 0xFF
        byte = stream.readByteNum()
    total += byte
    return total

def uncompressed_data_location(opcode: int, stream:BinaryStream) -> tuple[bytes, int, int, int]:

    if opcode >= 0x00  and opcode <= 0x0F:
        logging.error("Bad Opcode in decompress bytes: '{opcode:#04x}'")
    elif opcode == 0x10:
        comp_bytes = read_long_compression_offset(stream) + 9
        comp_offset, lit_length = read_two_byte_offset(stream)
        comp_offset += 0x3FFF
    elif opcode == 0x11:
        logging.error("Terminate Opcode in decompress bytes: '{opcode:#04x}'")
    elif opcode >= 0x12 and opcode <= 0x1F:
        comp_bytes = (opcode & 0x0F) + 2
        comp_offset, lit_length = read_two_byte_offset(stream)
        comp_offset += 0x3FFF
    elif opcode == 0x20:
        comp_bytes = read_long_compression_offset(stream) + 0x21
        comp_offset, lit_length = read_two_byte_offset(stream)
    elif opcode >= 0x21 and opcode <= 0x3F:
        comp_bytes = opcode - 0x1E
        comp_offset, lit_length = read_two_byte_offset(stream)
    elif opcode >= 0x40 and opcode <= 0xFF:
        comp_bytes = ((opcode & 0xF0) >> 4) - 1
        opcode2 = stream.readByteNum()
        comp_offset = (opcode2 << 2) | ((opcode & 0x0C) >> 2)
        lit_length = opcode & 0x03
    else:
        # Getting here shouldn't be possible.
        # The block above accounts for every
        # possible value of a byte.
        logging.error("Impossible value for opcode in decompress_bytes: '{opcode:#04x}'")

    if lit_length != 0:
        opcode = 0x00
    else:
        lit_length, opcode = read_literal_length(stream)

    return (opcode, comp_bytes, comp_offset, lit_length)

def decompress_bytes(bytez, decompressed_size):
    verbose_on = (decompressed_size == 1572)
    decompressed = bytearray()
    stream = BinaryStream(bytez)
    lit_length, opcode = read_literal_length(stream)
    decompressed.extend(stream.readBytes(lit_length))

    if verbose_on: print(f'op: {opcode:#04x}, lit: {lit_length}, comp_bytes:  , comp_offset: ')
    og_lit_length = lit_length
    while opcode != "":
        old_opcode = opcode
        if opcode ==0x00: opcode = stream.readByteNum()
        if opcode == 0x11: break
        old2 = opcode
        opcode, comp_bytes, comp_offset, lit_length = uncompressed_data_location(opcode, stream)
        if verbose_on: print(f'({(decompressed_size + 1014 + og_lit_length) - len(decompressed)}) -O {old_opcode:#04x} <O {old2:#04x} <F {comp_offset:#04x} <C {comp_bytes}, <L {lit_length}')
        distance = comp_offset + 1    
        for _ in range(comp_bytes): decompressed.append(decompressed[-distance])
        if lit_length:
            bytez = stream.readBytes(lit_length)
            if verbose_on: print(opcode, lit_length, hex_dump_bytes(bytez))
            decompressed.extend(bytez)
        
        if verbose_on: print(f"***\n{fancy_hex_dump_bytes(decompressed)}\n***")

    logging.debug(f"decompress: {len(decompressed)}, {decompressed_size}")

    if verbose_on: print(fancy_hex_dump_bytes(decompressed))

    return decompressed

def read_system_section_map(stream):
    page_number = stream.readInt32()
    sections = []
    section_address = 0x100 # starting address

    while page_number is not None:
        section_size = stream.readInt32()
        parent = None
        left = None
        right = None
        if page_number < 0:
            parent = stream.readInt32()
            left = stream.readInt32()
            right = stream.readInt32()
            _ = stream.readInt32() # zero

        sections.append(r2004_SystemSectionMapEntry(page_number, section_address, section_size, parent, left, right))
        section_address += section_size
        page_number = stream.readInt32()

    return sections


def read_data_section_map(stream: BinaryStream):
    results = []
    num_descriptions = log('num_descriptions', stream.readInt32())
    _                = log('0x02',             stream.readInt32(), True)
    _                = log('0x7400',           stream.readInt32(), True)
    _                = log('0x00',             stream.readInt32(), True)
    _                = log('unknown',          stream.readInt32())

    for _ in range(num_descriptions):
        desc = r2004_PageDescription()
        desc.read(stream)
        results.append(desc)

    return results

def read_map_header(stream: BinaryStream):
    section_page_type             = log('section_page_type',            stream.readInt32(), True)
    decompressed_size_of_data     = log('decompressed_size_of_data',    stream.readInt32())
    compressed_size_of_data       = log('compressed_size_of_data',      stream.readInt32())
    _                             = log('compression_type 0x02',        stream.readInt32(), True)
    _                             = log('section_page_checksum',        stream.readInt32(), True)

    # The second header looks like the first execpt with a zero compressed/uncompressed data block
    if not compressed_size_of_data: return (None, section_page_type)

    compressed_bytes = stream.readBytes(compressed_size_of_data)
    decompressed = decompress_bytes(compressed_bytes, decompressed_size_of_data)
    stream = BinaryStream(decompressed)
    return stream, section_page_type

def read_ac1018_data_header(f: io.BytesIO, address):
    result = r2004_DataHeader()
    result.read(f, address)
    return result

def read_ac1018_section(f: io.BytesIO, header:r2004_Header):
    system_section_map_marker = 0x41630e3b
    data_section_map_marker = 0x4163003b    
    stream = BinaryStream(f)
    f.seek(header.section_map_address)

    stream2, section_type = read_map_header(stream)

    is_page_map = section_type == system_section_map_marker
    is_data_section_map = section_type == data_section_map_marker

    log("Is page map",    is_page_map)
    log("Is section map", is_data_section_map)

    if not is_page_map: logging.error(f"Expected page map.  Got: {section_type}")

    header.system_sections_map = read_system_section_map(stream2)
    logging.debug(f'head num sections: {header.num_sections}, found in map: {len(header.system_sections_map)}')
    # for entry in header.system_sections_map:
    #     data = read_ac1018_data_header(f, entry.address)
    #     print(data)

    data_entry = header.get_data_entry()
    f.seek(data_entry.address)
    stream3, section_type = read_map_header(stream)
    header.data_sections_map = read_data_section_map(stream3)

def read_ac1018_header(f):
    header = r2004_Header()
    stream = BinaryStream(f)
    log(hex_dump_bytes(                                                       stream.readBytes(5)))
    header.version                      = log('version',                      stream.readByteNum())
    header.tag                          = log('tag',                          stream.readByteNum())
    header.preview_address              = log('preview_address',              stream.readInt32())
    header.acad_version                 = log('acad_version',                 stream.readByteNum())
    header.acad_release                 = log('acad_release',                 stream.readByteNum())
    header.code_page                    = log('code_page',                    stream.readInt16())
    log(hex_dump_bytes(                                                       stream.readBytes(3)))
    header.encrypt_data                 = log('encrypt_data',                 stream.readBool())
    header.encrypt_properties           = log('encrypt_properties',           stream.readBool())
    header.sign_data                    = log('sign_data',                    stream.readBool())
    header.add_timestamp                = log('add_timestamp',                stream.readBool())
    log(hex_dump_bytes(                                                       stream.readBytes(4)))
    header.summary_address              = log('summary address',              stream.readInt32())
    header.vbaproject_address           = log('vbaproject_address',           stream.readInt32())
    log(hex(0x80),                                                            stream.readInt32(), True)
    log(hex_dump_bytes(                                                       stream.readBytes(0x54)))

    decrypted = decrypt_header(stream.readBytes(0x6c))
    stream2 = BinaryStream(decrypted)
    
    header.file_id                      = log('file_id',                      stream2.readStringBytes(12))
    log(hex(0x00),                                                            stream2.readInt32(), True)
    log(hex(0x6c),                                                            stream2.readInt32(), True)
    log(hex(0x04),                                                            stream2.readInt32(), True)
    header.root_tree_node_gap           = log("root_tree_node_gap",           stream2.readInt32())
    header.lower_left_node_gap          = log("lower_left_node_gap",          stream2.readInt32())
    header.lower_right_node_gap         = log("lower_right_node_gap",         stream2.readInt32())
    unknown                             = log("unknown",                      stream2.readInt32())
    header.last_section_page_id         = log("last_section_page_id",         stream2.readInt32())
    header.last_section_page_end_address= log("last_section_page_end_address",stream2.readInt64())
    header.second_header_address        = log("second_header_address",        stream2.readInt64())
    header.num_gaps                     = log("num_gaps",                     stream2.readInt32())
    header.num_sections                 = log("num_sections",                 stream2.readInt32())
    log(hex(0x20),                                                            stream2.readInt32(), True)
    log(hex(0x80),                                                            stream2.readInt32(), True)
    log(hex(0x40),                                                            stream2.readInt32(), True)
    header.section_map_id              = log("section_map_id",                stream2.readInt32())
    header.section_map_address         = log("section_map_address",           stream2.readInt64() + 0x100, True)
    header.section_info_id             = log("section_info_id",               stream2.readInt32())
    header.section_array_size          = log("section_array_size",            stream2.readInt32())
    header.gap_array_size              = log("gap_array_size",                stream2.readInt32())
    header.crc32                       = log("crc32",                         stream2.readInt32(), True)
    padding                            = log("padding",        decrypt_header(stream.readBytes(12)),True)

    return header

def read_ac1018(f):
    header = read_ac1018_header(f)
    read_ac1018_section(f, header)

def read_file(f):
    version = ""
    if (bytes := f.read(6)) is not None:
        version = bytes.decode("utf-8")
        logging.info(version)
    
    if version == "AC1018":
        read_ac1018(f)

def parse_file(filename):
    filename = "test_data/file1/F812452.dwg"
    with open(filename, "rb") as f:
        read_file(f)
    # import libredwg
    # a = libredwg.LibreDWG.Dwg_Data()
    # a.object = libredwg.LibreDWG.new_Dwg_Object_Array(1000)
    # error = libredwg.LibreDWG.dwg_read_file(filename, a)

    # if (error > 0): # critical errors
    #     print("Error: ", error)
    #     if (error > 127):
    #         exit()

    # print(".dwg version: %s" % a.header.version)
    # print("Num objects: %d " % a.num_objects)

    # #XXX TODO Error: Dwg_Object_LAYER_CONTROL object has no attribute 'tio'
    # #print "Num layers: %d" % a.layer_control.tio.object.tio.LAYER_CONTROL.num_entries

    # #XXX ugly, but works
    # for i in range(0, a.num_objects):
    #     obj = libredwg.LibreDWG.Dwg_Object_Array_getitem(a.object, i)
    #     print(" Supertype: " ,   obj.supertype)
    #     print("      Type: " ,   obj.type)



if __name__ == '__main__':

    args = get_arguments()
    logging.basicConfig(level=args.log_level.upper())
    # text_pieces = get_text_segments(args.filename)
    # end_char = "\\n" if args.one_line else "\n"
    # dump_kwargs = {} if args.one_line else {'indent': 3}
    # if not args.print_json:
    #     for text in text_pieces: 
    #         if args.no_location:
    #             print(text['text'].replace("\n", "\\n"), end=end_char)
    #         else:
    #             print(f'text: "{text['text'].replace("\n", "\\n")}", loc:{text['location']}', end=end_char)
    # else:
    #     print(json.dumps(text_pieces, **dump_kwargs))
    parse_file(args.filename)
