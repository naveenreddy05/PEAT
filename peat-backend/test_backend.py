#!/usr/bin/env python3
"""
Quick test script for PEAT backend
Tests the analysis engine without HTTP server
"""

import os
import sys
from modules.malware_classifier import MalwareClassifier

def test_analysis(file_path):
    """Test analysis on a file"""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False

    print("\n" + "="*60)
    print("PEAT Backend Test")
    print("="*60)
    print(f"File: {file_path}")
    print(f"Size: {os.path.getsize(file_path)} bytes")
    print("="*60 + "\n")

    try:
        # Initialize classifier
        classifier = MalwareClassifier(yara_rules_dir='yara_rules')

        # Run analysis
        result = classifier.analyze(file_path)

        if not result.get('success'):
            print(f"❌ Analysis failed: {result.get('error')}")
            return False

        # Display results
        print("\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)

        classification = result.get('classification', {})
        print(f"\n📊 Classification:")
        print(f"   Family:     {classification.get('family', 'Unknown')}")
        print(f"   Category:   {classification.get('category', 'Unknown')}")
        print(f"   Severity:   {classification.get('severity', 'Unknown')}")
        print(f"   Risk Score: {classification.get('risk_score', 0)}/100")
        print(f"   Confidence: {classification.get('confidence', 0)}%")
        print(f"   Is Malware: {classification.get('is_malware', False)}")

        iocs = result.get('iocs', {})
        print(f"\n🔍 IoCs Extracted:")
        print(f"   IPs:        {len(iocs.get('ips', []))}")
        print(f"   URLs:       {len(iocs.get('urls', []))}")
        print(f"   Suspicious: {len(iocs.get('suspicious_strings', []))}")
        print(f"   Ports:      {len(iocs.get('ports', []))}")

        signatures = result.get('signatures', {})
        if signatures.get('matched'):
            print(f"\n⚠️  YARA Matches:")
            for match in signatures.get('matches', [])[:3]:
                print(f"   - {match.get('rule')} ({match.get('namespace')})")

        entropy = result.get('entropy', {})
        print(f"\n📈 Entropy Analysis:")
        print(f"   Overall:    {entropy.get('overall', 0)}")
        print(f"   Is Packed:  {entropy.get('is_packed', False)}")

        threats = result.get('threats', [])
        print(f"\n🚨 Threats Found: {len(threats)}")
        for threat in threats[:3]:
            print(f"   - [{threat.get('severity')}] {threat.get('name')}")

        print("\n" + "="*60)
        print("✅ Test completed successfully!")
        print("="*60 + "\n")

        return True

    except Exception as e:
        print(f"\n❌ Test failed with error:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    # Test file path
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
    else:
        # Look for test files in peat-app uploads
        test_dir = '../peat-app/uploads'
        if os.path.exists(test_dir):
            files = [f for f in os.listdir(test_dir) if f.endswith('.bin')]
            if files:
                test_file = os.path.join(test_dir, files[0])
                print(f"Using test file: {test_file}")
            else:
                print("No test files found in peat-app/uploads/")
                print("Usage: python test_backend.py <file_path>")
                sys.exit(1)
        else:
            print("Usage: python test_backend.py <file_path>")
            sys.exit(1)

    success = test_analysis(test_file)
    sys.exit(0 if success else 1)
