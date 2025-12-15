import { NextRequest, NextResponse } from 'next/server';
import { writeFile, mkdir } from 'fs/promises';
import * as path from 'path';
import { existsSync } from 'fs';

// Configure upload directory
const UPLOAD_DIR = path.join(process.cwd(), 'uploads');

// Ensure upload directory exists
async function ensureUploadDir() {
  if (!existsSync(UPLOAD_DIR)) {
    await mkdir(UPLOAD_DIR, { recursive: true });
  }
}

// Validate file type and size
function validateFile(file: File): { valid: boolean; error?: string } {
  const MAX_SIZE = 500 * 1024 * 1024; // 500MB
  const ALLOWED_EXTENSIONS = ['.dump', '.bin', '.mem', '.raw', '.dmp', '.lime', '.elf', '.exe', '.out', '.o', '.so', '.dylib'];

  // Check size
  if (file.size > MAX_SIZE) {
    return {
      valid: false,
      error: `File too large. Maximum size is ${MAX_SIZE / (1024 * 1024)}MB`
    };
  }

  // Check extension (allow files without extension for Linux binaries)
  const ext = path.extname(file.name).toLowerCase();
  if (ext && !ALLOWED_EXTENSIONS.includes(ext)) {
    return {
      valid: false,
      error: `Invalid file type. Allowed: binary files (.bin, .elf, .exe, etc.)`
    };
  }

  return { valid: true };
}

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return NextResponse.json(
        { success: false, error: 'No file provided' },
        { status: 400 }
      );
    }

    // Validate file
    const validation = validateFile(file);
    if (!validation.valid) {
      return NextResponse.json(
        { success: false, error: validation.error },
        { status: 400 }
      );
    }

    // Ensure upload directory exists
    await ensureUploadDir();

    // Generate unique filename
    const timestamp = Date.now();
    const sanitizedName = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
    const filename = `${timestamp}_${sanitizedName}`;
    const filepath = path.join(UPLOAD_DIR, filename);

    // Convert file to buffer and save
    const bytes = await file.arrayBuffer();
    const buffer = Buffer.from(bytes);

    await writeFile(filepath, buffer);

    console.log(`File uploaded successfully: ${filepath}`);

    return NextResponse.json({
      success: true,
      data: {
        fileId: timestamp.toString(),
        filename: filename,
        filepath: filepath,
        size: file.size,
        uploadedAt: new Date().toISOString()
      },
      message: 'File uploaded successfully'
    });

  } catch (error: any) {
    console.error('Upload error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Upload failed' },
      { status: 500 }
    );
  }
}

// Optional: Add GET endpoint to check upload status or retrieve file info
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const fileId = searchParams.get('fileId');

  if (!fileId) {
    return NextResponse.json(
      { success: false, error: 'File ID required' },
      { status: 400 }
    );
  }

  // In a real app, you'd query a database here
  return NextResponse.json({
    success: true,
    data: {
      fileId,
      status: 'uploaded',
      message: 'File is ready for analysis'
    }
  });
}
