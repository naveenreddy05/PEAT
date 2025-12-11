"""
Entropy Analysis Module
Calculates entropy to detect packed/encrypted malware sections
"""

import math
from collections import Counter

class EntropyAnalyzer:

    @staticmethod
    def calculate_entropy(data):
        """Calculate Shannon entropy of byte sequence"""
        if not data:
            return 0.0

        # Count byte frequencies
        counter = Counter(data)
        length = len(data)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def analyze_file(file_path, chunk_size=1024):
        """Analyze entropy across file in chunks"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Overall file entropy
            overall_entropy = EntropyAnalyzer.calculate_entropy(data)

            # Chunk-based entropy analysis
            chunks = []
            total_size = len(data)

            for i in range(0, total_size, chunk_size):
                chunk_data = data[i:i+chunk_size]
                chunk_entropy = EntropyAnalyzer.calculate_entropy(chunk_data)

                chunks.append({
                    'offset': hex(i),
                    'size': len(chunk_data),
                    'entropy': round(chunk_entropy, 3)
                })

            # Calculate statistics
            entropies = [c['entropy'] for c in chunks]
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0
            max_entropy = max(entropies) if entropies else 0
            min_entropy = min(entropies) if entropies else 0

            # High entropy chunks (possible encryption/packing)
            high_entropy_chunks = [c for c in chunks if c['entropy'] > 7.0]

            return {
                'overall': round(overall_entropy, 3),
                'average': round(avg_entropy, 3),
                'max': round(max_entropy, 3),
                'min': round(min_entropy, 3),
                'high_entropy_chunks': len(high_entropy_chunks),
                'is_packed': overall_entropy > 7.2,  # Threshold for packed binaries
                'chunks': chunks[:20]  # Limit output
            }

        except Exception as e:
            raise Exception(f"Entropy analysis failed: {str(e)}")

    @staticmethod
    def analyze_sections(file_path, sections):
        """Analyze entropy for specific ELF sections"""
        section_entropies = []

        try:
            with open(file_path, 'rb') as f:
                for section in sections:
                    if section['size'] > 0:
                        f.seek(section['offset'])
                        data = f.read(section['size'])

                        entropy = EntropyAnalyzer.calculate_entropy(data)

                        section_entropies.append({
                            'name': section['name'],
                            'entropy': round(entropy, 3),
                            'size': section['size'],
                            'suspicious': entropy > 7.0
                        })
        except Exception as e:
            print(f"Section entropy analysis error: {e}")

        return section_entropies
