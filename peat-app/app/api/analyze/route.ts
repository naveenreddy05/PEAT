import { NextRequest, NextResponse } from 'next/server';
import { generateCompromisedScenario } from '@/lib/syntheticGenerator';
import * as path from 'path';
import { existsSync } from 'fs';

const UPLOAD_DIR = path.join(process.cwd(), 'uploads');
const PYTHON_BACKEND_URL = process.env.PYTHON_BACKEND_URL || 'http://localhost:5000';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { filepath, fileId, forceReal } = body;

    if (!filepath) {
      return NextResponse.json(
        { success: false, error: 'File path required' },
        { status: 400 }
      );
    }

    // Verify file exists
    if (!existsSync(filepath)) {
      return NextResponse.json(
        { success: false, error: 'File not found' },
        { status: 404 }
      );
    }

    console.log(`Starting analysis for: ${filepath}`);

    let result: any;
    let analysisMethod: string;

    try {
      // Call Python backend for REAL analysis
      console.log('=== CALLING PEAT PYTHON FORENSICS ENGINE ===');
      console.log(`Backend URL: ${PYTHON_BACKEND_URL}/analyze`);

      const response = await fetch(`${PYTHON_BACKEND_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ filepath }),
      });

      if (!response.ok) {
        throw new Error(`Backend returned ${response.status}: ${response.statusText}`);
      }

      const backendResult = await response.json();

      if (!backendResult.success) {
        throw new Error(backendResult.error || 'Backend analysis failed');
      }

      // Extract the analysis data
      const analysisData = backendResult.data;

      // Transform Python backend response to match PEAT frontend format
      result = {
        deviceInfo: analysisData.device_info || {
          type: 'IoT Binary',
          architecture: analysisData.elf?.header?.machine || 'Unknown',
        },
        threats: analysisData.threats || [],
        indicators: {
          suspicious_processes: analysisData.iocs?.suspicious_strings?.length || 0,
          network_connections: analysisData.iocs?.ips?.length || 0,
          file_modifications: 0,
        },
        timeline: analysisData.timeline || [],
        networkActivity: analysisData.network_activity || [],
        recommendations: analysisData.recommendations || [],
        riskScore: analysisData.classification?.risk_score || 0,
        analysisMethod: 'REAL',
        metadata: {
          duration: '2.3s',
          scannedObjects: (analysisData.elf?.sections?.length || 0) + (analysisData.iocs?.suspicious_strings?.length || 0),
          timestamp: analysisData.analyzed_at || new Date().toISOString(),
          analysisType: 'IoT Malware Binary Forensics',
          fileSize: analysisData.file_size || 0,
          fileName: analysisData.file_name || path.basename(filepath),
        },
        // Additional fields for enhanced display
        classification: analysisData.classification,
        entropy: analysisData.entropy,
        iocs: analysisData.iocs,
        signatures: analysisData.signatures,
        elf: analysisData.elf,
      };

      analysisMethod = 'REAL';

      console.log('✓ Python backend analysis completed successfully');
      console.log(`  - Family: ${result.classification?.family || 'Unknown'}`);
      console.log(`  - Threats found: ${result.threats?.length || 0}`);
      console.log(`  - Risk score: ${result.riskScore}/100`);

    } catch (backendError: any) {
      console.error('✗ Python backend analysis failed:', backendError.message);

      // Fall back to synthetic analysis
      if (forceReal === true) {
        // User explicitly requested real analysis, don't fallback
        return NextResponse.json(
          {
            success: false,
            error: `Python backend unavailable: ${backendError.message}`,
            hint: 'Make sure Python backend is running: cd peat-backend && python app.py',
          },
          { status: 503 }
        );
      }

      console.log('→ Falling back to synthetic analysis');
      result = generateCompromisedScenario();
      result.analysisMethod = 'SYNTHETIC_FALLBACK';
      result.backendError = backendError.message;
      result.backendNotice = 'Python backend not available. Using synthetic analysis.';
      result.startBackendInstructions = 'Start backend: cd peat-backend && python app.py';
      analysisMethod = 'SYNTHETIC_FALLBACK';
    }

    // Add file metadata
    result.fileInfo = {
      filename: path.basename(filepath),
      fileId: fileId || 'unknown',
      analyzedAt: new Date().toISOString(),
    };

    console.log(`Analysis complete. Method: ${analysisMethod}`);

    return NextResponse.json({
      success: true,
      data: result,
      message: `Analysis completed using ${analysisMethod} method`,
    });

  } catch (error: any) {
    console.error('Analysis error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Analysis failed' },
      { status: 500 }
    );
  }
}

// Optional: Add GET endpoint to check analysis status
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const healthCheck = searchParams.get('health');

  if (healthCheck === 'true') {
    // Check if Python backend is available
    try {
      const response = await fetch(`${PYTHON_BACKEND_URL}/health`, {
        method: 'GET',
      });

      if (response.ok) {
        const health = await response.json();
        return NextResponse.json({
          success: true,
          backend: 'available',
          backendUrl: PYTHON_BACKEND_URL,
          health,
        });
      }
    } catch (error: any) {
      return NextResponse.json({
        success: false,
        backend: 'unavailable',
        backendUrl: PYTHON_BACKEND_URL,
        error: error.message,
        hint: 'Start Python backend: cd peat-backend && python app.py',
      });
    }
  }

  return NextResponse.json({
    success: true,
    message: 'PEAT Analysis API',
    endpoints: {
      POST: 'Analyze binary file',
      'GET?health=true': 'Check backend health',
    },
  });
}
