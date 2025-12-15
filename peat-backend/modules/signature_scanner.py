"""
YARA Signature Scanner
Scans binaries against IoT malware signature database
"""

import yara
import os
import glob

class SignatureScanner:

    def __init__(self, rules_dir='yara_rules'):
        self.rules_dir = rules_dir
        self.compiled_rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile all YARA rules from the rules directory"""
        try:
            rule_files = glob.glob(os.path.join(self.rules_dir, '*.yar'))

            if not rule_files:
                print(f"Warning: No YARA rules found in {self.rules_dir}")
                return

            # Build rules dict for compilation
            rules_dict = {}
            for rule_file in rule_files:
                namespace = os.path.basename(rule_file).replace('.yar', '')
                rules_dict[namespace] = rule_file

            self.compiled_rules = yara.compile(filepaths=rules_dict)
            print(f"Compiled {len(rule_files)} YARA rule files")

        except Exception as e:
            print(f"YARA compilation error: {e}")
            self.compiled_rules = None

    def scan(self, file_path):
        """Scan a file against all YARA rules"""
        if not self.compiled_rules:
            return {
                'matched': False,
                'matches': [],
                'error': 'No YARA rules compiled'
            }

        try:
            matches = self.compiled_rules.match(file_path)

            results = {
                'matched': len(matches) > 0,
                'match_count': len(matches),
                'matches': []
            }

            for match in matches:
                match_data = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }

                # Extract matched strings (limit to first 10)
                for string_match in match.strings[:10]:
                    # YARA StringMatch objects have attributes, not tuple indices
                    for instance in string_match.instances:
                        match_data['strings'].append({
                            'offset': hex(instance.offset),
                            'identifier': string_match.identifier,
                            'data': instance.matched_data.decode('utf-8', errors='ignore')[:100]
                        })
                        break  # Only take first instance of each string

                results['matches'].append(match_data)

            return results

        except Exception as e:
            return {
                'matched': False,
                'matches': [],
                'error': str(e)
            }

    def get_malware_family(self, matches):
        """Determine malware family from YARA matches"""
        if not matches:
            return None

        # Priority order for family determination
        families = {
            'Mirai': 'CRITICAL',
            'Gafgyt': 'CRITICAL',
            'Qbot': 'CRITICAL',
            'Cryptominer': 'HIGH',
            'Backdoor': 'CRITICAL',
            'Reverse_Shell': 'CRITICAL',
            'Rootkit': 'CRITICAL'
        }

        for match in matches:
            family = match.get('meta', {}).get('family', '')
            if family in families:
                return {
                    'family': family,
                    'severity': families[family],
                    'rule': match['rule'],
                    'description': match.get('meta', {}).get('description', '')
                }

        # Fallback to first match
        if matches:
            first_match = matches[0]
            return {
                'family': first_match.get('meta', {}).get('family', 'Unknown'),
                'severity': first_match.get('meta', {}).get('severity', 'MEDIUM'),
                'rule': first_match['rule'],
                'description': first_match.get('meta', {}).get('description', '')
            }

        return None
