"""
PEAT Backend API
Post-Exploitation Analysis Tool - IoT Malware Forensics Engine
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
from datetime import datetime

# Add modules to path
sys.path.insert(0, os.path.dirname(__file__))

from modules.malware_classifier import MalwareClassifier

app = Flask(__name__)
CORS(app)  # Enable CORS for Next.js frontend

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), 'yara_rules')
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize classifier
classifier = MalwareClassifier(yara_rules_dir=YARA_RULES_DIR)

@app.route('/', methods=['GET'])
def index():
    """API health check"""
    return jsonify({
        'service': 'PEAT Forensics Engine',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            '/analyze': 'POST - Analyze binary file',
            '/health': 'GET - Health check'
        }
    })

@app.route('/health', methods=['GET'])
def health():
    """Detailed health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'yara_rules_loaded': os.path.exists(YARA_RULES_DIR),
        'upload_dir_writable': os.access(UPLOAD_FOLDER, os.W_OK)
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Analyze uploaded binary file for malware

    Accepts:
    - Multipart file upload (file)
    - OR JSON with file path (filepath)

    Returns:
    - Comprehensive malware analysis report
    """
    try:
        file_path = None
        uploaded_file = False

        # Check if file uploaded
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400

            # Save uploaded file
            filename = f"{datetime.now().timestamp()}_{file.filename}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            uploaded_file = True

        # Check if filepath provided in JSON
        elif request.is_json:
            data = request.get_json()
            file_path = data.get('filepath')
            if not file_path:
                return jsonify({'success': False, 'error': 'No filepath provided'}), 400

        else:
            return jsonify({'success': False, 'error': 'No file or filepath provided'}), 400

        # Verify file exists
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'File not found'}), 404

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            return jsonify({'success': False, 'error': f'File too large (max {MAX_FILE_SIZE} bytes)'}), 413

        print(f"\n{'='*60}")
        print(f"ANALYZING: {os.path.basename(file_path)}")
        print(f"Size: {file_size} bytes")
        print(f"{'='*60}\n")

        # Perform analysis
        results = classifier.analyze(file_path)

        if not results.get('success'):
            return jsonify(results), 500

        # Clean up uploaded file if needed
        if uploaded_file and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Warning: Could not delete uploaded file: {e}")

        print(f"\n{'='*60}")
        print(f"ANALYSIS COMPLETE")
        print(f"Family: {results['classification']['family']}")
        print(f"Risk Score: {results['classification']['risk_score']}/100")
        print(f"Threats: {len(results['threats'])}")
        print(f"{'='*60}\n")

        return jsonify({
            'success': True,
            'data': results,
            'message': 'Analysis completed successfully'
        })

    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/synthetic/<scenario>', methods=['GET'])
def synthetic_scenario(scenario):
    """
    Return pre-defined synthetic scenarios for educational purposes
    This maintains compatibility with your existing PEAT demo
    """
    # You can keep your existing synthetic generator for teaching
    scenarios = {
        'mirai': {
            'family': 'Mirai',
            'risk_score': 95,
            'severity': 'CRITICAL'
        },
        'clean': {
            'family': 'Clean',
            'risk_score': 5,
            'severity': 'LOW'
        }
    }

    if scenario in scenarios:
        return jsonify({
            'success': True,
            'data': scenarios[scenario],
            'synthetic': True
        })
    else:
        return jsonify({'success': False, 'error': 'Unknown scenario'}), 404

if __name__ == '__main__':
    print("\n" + "="*60)
    print("PEAT Forensics Engine Starting...")
    print("="*60)
    print(f"Upload folder: {UPLOAD_FOLDER}")
    print(f"YARA rules: {YARA_RULES_DIR}")
    print("="*60 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
