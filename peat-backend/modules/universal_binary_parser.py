"""
Universal Binary Parser Module
Supports ELF (Linux/IoT), Mach-O (macOS), and PE (Windows)
"""

import os
import struct

class UniversalBinaryParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_type = None

    def detect_format(self):
        """Detect binary format"""
        with open(self.file_path, 'rb') as f:
            magic = f.read(4)

            # ELF magic: 0x7f 'E' 'L' 'F'
            if magic[:4] == b'\x7fELF':
                return 'ELF'

            # Mach-O magic (various)
            if magic[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',  # Mach-O 32/64 bit
                             b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',  # Reverse byte order
                             b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca']:  # Universal binary
                return 'Mach-O'

            # PE magic: 'MZ'
            if magic[:2] == b'MZ':
                return 'PE'

            return 'Unknown'

    def parse(self):
        """Parse binary and extract comprehensive metadata"""
        self.file_type = self.detect_format()

        if self.file_type == 'ELF':
            return self._parse_elf()
        elif self.file_type == 'Mach-O':
            return self._parse_macho()
        elif self.file_type == 'PE':
            return self._parse_pe()
        else:
            return self._parse_generic()

    def _parse_elf(self):
        """Parse ELF using pyelftools"""
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection

            with open(self.file_path, 'rb') as f:
                elf = ELFFile(f)

                sections = []
                for section in elf.iter_sections():
                    sections.append({
                        'name': section.name,
                        'type': section['sh_type'],
                        'size': section['sh_size']
                    })

                symbols = []
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol.name:
                                symbols.append({'name': symbol.name})
                                if len(symbols) >= 50:
                                    break

                return {
                    'file_info': {
                        'path': self.file_path,
                        'size': os.path.getsize(self.file_path),
                        'name': os.path.basename(self.file_path),
                        'format': 'ELF'
                    },
                    'header': {
                        'class': elf.elfclass,
                        'machine': elf.header['e_machine'],
                        'type': elf.header['e_type']
                    },
                    'sections': sections,
                    'symbols': symbols,
                    'strings': self._extract_strings()
                }
        except Exception as e:
            return self._parse_generic()

    def _parse_macho(self):
        """Parse Mach-O format (macOS binaries)"""
        stat = os.stat(self.file_path)

        with open(self.file_path, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]

            # Determine architecture
            if magic in [0xfeedface, 0xcefaedfe]:
                arch = 'x86'
            elif magic in [0xfeedfacf, 0xcffaedfe]:
                arch = 'x86_64'
            else:
                arch = 'Unknown'

        return {
            'file_info': {
                'path': self.file_path,
                'size': stat.st_size,
                'name': os.path.basename(self.file_path),
                'format': 'Mach-O'
            },
            'header': {
                'class': '64-bit' if arch == 'x86_64' else '32-bit',
                'machine': arch,
                'type': 'executable'
            },
            'sections': [{'name': '__TEXT', 'type': 'code', 'size': stat.st_size}],
            'segments': [],
            'symbols': [],
            'strings': self._extract_strings(),
            'dynamic': []
        }

    def _parse_pe(self):
        """Parse PE format (Windows binaries)"""
        stat = os.stat(self.file_path)

        return {
            'file_info': {
                'path': self.file_path,
                'size': stat.st_size,
                'name': os.path.basename(self.file_path),
                'format': 'PE'
            },
            'header': {
                'class': 'PE',
                'machine': 'x86',
                'type': 'executable'
            },
            'sections': [],
            'symbols': [],
            'strings': self._extract_strings(),
            'dynamic': []
        }

    def _parse_generic(self):
        """Generic parser for unknown formats"""
        stat = os.stat(self.file_path)

        return {
            'file_info': {
                'path': self.file_path,
                'size': stat.st_size,
                'name': os.path.basename(self.file_path),
                'format': self.file_type or 'Unknown'
            },
            'header': {
                'class': 'Unknown',
                'machine': 'Unknown',
                'type': 'binary'
            },
            'sections': [],
            'segments': [],
            'symbols': [],
            'strings': self._extract_strings(),
            'dynamic': []
        }

    def _extract_strings(self, min_length=4):
        """Extract printable strings from the binary"""
        strings = []
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                current_string = []

                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string.append(chr(byte))
                    else:
                        if len(current_string) >= min_length:
                            strings.append(''.join(current_string))
                        current_string = []

                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
        except Exception as e:
            print(f"String extraction error: {e}")

        return strings[:200]  # Limit to first 200 strings
