"""
ELF Binary Parser Module
Extracts metadata, sections, symbols, and strings from ELF binaries
"""

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os

class ELFParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.elf = None

    def parse(self):
        """Parse ELF binary and extract comprehensive metadata"""
        try:
            with open(self.file_path, 'rb') as f:
                self.elf = ELFFile(f)

                return {
                    'file_info': self._get_file_info(),
                    'header': self._get_header_info(),
                    'sections': self._get_sections(),
                    'segments': self._get_segments(),
                    'symbols': self._get_symbols(),
                    'strings': self._extract_strings(),
                    'dynamic': self._get_dynamic_info()
                }
        except Exception as e:
            raise Exception(f"Failed to parse ELF: {str(e)}")

    def _get_file_info(self):
        """Get basic file information"""
        stat = os.stat(self.file_path)
        return {
            'path': self.file_path,
            'size': stat.st_size,
            'name': os.path.basename(self.file_path)
        }

    def _get_header_info(self):
        """Extract ELF header information"""
        header = self.elf.header
        return {
            'class': self.elf.elfclass,  # 32 or 64 bit
            'data': self.elf.little_endian and 'Little Endian' or 'Big Endian',
            'machine': header['e_machine'],
            'type': header['e_type'],
            'entry_point': hex(header['e_entry']),
            'flags': hex(header['e_flags'])
        }

    def _get_sections(self):
        """Extract all section information"""
        sections = []
        for section in self.elf.iter_sections():
            sections.append({
                'name': section.name,
                'type': section['sh_type'],
                'addr': hex(section['sh_addr']),
                'offset': section['sh_offset'],
                'size': section['sh_size'],
                'flags': section['sh_flags']
            })
        return sections

    def _get_segments(self):
        """Extract program header/segment information"""
        segments = []
        for segment in self.elf.iter_segments():
            segments.append({
                'type': segment['p_type'],
                'offset': segment['p_offset'],
                'vaddr': hex(segment['p_vaddr']),
                'paddr': hex(segment['p_paddr']),
                'filesz': segment['p_filesz'],
                'memsz': segment['p_memsz'],
                'flags': segment['p_flags']
            })
        return segments

    def _get_symbols(self):
        """Extract symbol table information"""
        symbols = []
        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name:
                        symbols.append({
                            'name': symbol.name,
                            'value': hex(symbol['st_value']),
                            'size': symbol['st_size'],
                            'type': symbol['st_info']['type'],
                            'bind': symbol['st_info']['bind']
                        })
        return symbols[:100]  # Limit to first 100 symbols

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

                # Don't forget last string
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
        except Exception as e:
            print(f"String extraction error: {e}")

        return strings[:200]  # Limit to first 200 strings

    def _get_dynamic_info(self):
        """Extract dynamic linking information"""
        dynamic_tags = []
        try:
            for section in self.elf.iter_sections():
                if section.name == '.dynamic':
                    for tag in section.iter_tags():
                        dynamic_tags.append({
                            'tag': tag.entry.d_tag,
                            'value': hex(tag.entry.d_val) if isinstance(tag.entry.d_val, int) else str(tag.entry.d_val)
                        })
        except Exception:
            pass

        return dynamic_tags
