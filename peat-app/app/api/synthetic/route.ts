import { NextRequest, NextResponse } from 'next/server';
import {
  generateCompromisedScenario,
  generateCleanScenario,
  generateSuspiciousScenario
} from '@/lib/syntheticGenerator';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { scenarioType } = body;

    // Simulate realistic analysis time (2-6 seconds)
    const analysisDelay = Math.floor(Math.random() * 4000) + 2000;
    await new Promise(resolve => setTimeout(resolve, analysisDelay));

    let result;

    switch (scenarioType) {
      case 'compromised':
      case 'mirai':
      case 'botnet':
        result = generateCompromisedScenario();
        break;
      case 'clean':
      case 'secure':
        result = generateCleanScenario();
        break;
      case 'suspicious':
      case 'medium':
        result = generateSuspiciousScenario();
        break;
      default:
        // Random scenario if not specified
        const scenarios = [generateCompromisedScenario, generateCleanScenario, generateSuspiciousScenario];
        result = scenarios[Math.floor(Math.random() * scenarios.length)]();
    }

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Synthetic scenario generated successfully'
    });
  } catch (error: any) {
    console.error('Synthetic generation error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to generate synthetic scenario' },
      { status: 500 }
    );
  }
}
