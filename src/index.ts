/**
 * File Scanner - A tool to scan files for potential security threats
 * @packageDocumentation
 */

import { fileTypeFromBuffer } from 'file-type';
import { validatePDF } from './validators/pdf-validator.js';
import { validatePNG, validateJPEG, validateGIF, validateSVG, validateWebP } from './validators/image-validators.js';
import { validateZIP, validateRAR, validateGZIP, validate7Z, validateTAR } from './validators/archive-validators.js';
import { validateScript, validatePE, validateELF, validateConfigFile } from './validators/script-validators.js';
import {
  ScanResult,
  Threat,
  ThreatType,
  FileCategory,
  ScanOptions,
  FileTypeInfo,
  FileMetadata,
} from './types.js';

/**
 * Scans a buffer for potential malicious content
 * @param buffer - File buffer to scan
 * @param options - Scanning options
 * @returns Promise resolving to scan results
 */
export async function scanFile(
  buffer: Buffer,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const {
    maxFileSize = 500 * 1024 * 1024, // 500MB default
    deepScan = true,
    fileName,
  } = options;

  const result: ScanResult = {
    fileName: fileName || 'buffer',
    isClean: true,
    threats: [],
    scannedAt: new Date(),
    fileSize: buffer.length,
  };

  try {
    // File size check
    if (buffer.length > maxFileSize) {
      result.threats.push({
        type: ThreatType.EXCESSIVE_SIZE,
        severity: 'high',
        description: `File exceeds maximum size (${buffer.length} > ${maxFileSize} bytes)`,
      });
      result.isClean = false;
      return result;
    }

    // Detect file type
    const detectedType = await fileTypeFromBuffer(buffer);
    
    // Categorize and validate
    if (detectedType) {
      result.fileType = categorizeFileType(detectedType.ext, detectedType.mime);
      
      if (deepScan) {
        const validationResult = await validateFileByType(buffer, result.fileType);
        result.threats.push(...validationResult.threats);
        result.metadata = {
          signatureValid: validationResult.metadata.signatureValid ?? false,
          checksPerformed: validationResult.metadata.checksPerformed ?? [],
          warnings: validationResult.metadata.warnings ?? [],
          ...validationResult.metadata,
        };
      }
    } else {
      // Try to detect by content patterns
      const manualDetection = detectFileTypeManually(buffer, fileName);
      if (manualDetection) {
        result.fileType = manualDetection;
        
        if (deepScan) {
          const validationResult = await validateFileByType(buffer, result.fileType);
          result.threats.push(...validationResult.threats);
          result.metadata = {
            signatureValid: validationResult.metadata.signatureValid ?? false,
            checksPerformed: validationResult.metadata.checksPerformed ?? [],
            warnings: validationResult.metadata.warnings ?? [],
            ...validationResult.metadata,
          };
        }
      } else {
        result.fileType = {
          ext: 'unknown',
          mime: 'application/octet-stream',
          category: FileCategory.UNKNOWN,
        };
        result.metadata = {
          signatureValid: false,
          checksPerformed: [],
          warnings: ['Unable to determine file type'],
        };
      }
    }

    // Universal checks
    performUniversalChecks(buffer, result);

    // Determine if file is clean
    result.isClean = result.threats.length === 0 || 
                     result.threats.every(t => t.severity === 'low');

  } catch (error) {
    result.threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'critical',
      description: `Error scanning file: ${(error as Error).message}`,
    });
    result.isClean = false;
  }

  return result;
}

/**
 * Categorize file type into security categories
 */
function categorizeFileType(ext: string, mime: string): FileTypeInfo {
  const category = getFileCategory(ext, mime);
  return { ext, mime, category };
}

/**
 * Get file category based on extension and MIME type
 */
function getFileCategory(ext: string, mime: string): FileCategory {
  if (mime === 'application/pdf') return FileCategory.PDF;
  
  if (mime.startsWith('image/')) return FileCategory.IMAGE;
  
  if (['zip', 'rar', 'tar', 'gz', 'bz2', '7z', 'xz'].includes(ext)) {
    return FileCategory.ARCHIVE;
  }
  
  if (['exe', 'dll', 'so', 'dylib', 'msi'].includes(ext)) {
    return FileCategory.EXECUTABLE;
  }
  
  if (['js', 'py', 'sh', 'ps1', 'vbs', 'bat', 'cmd'].includes(ext)) {
    return FileCategory.SCRIPT;
  }
  
  if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods'].includes(ext)) {
    return FileCategory.DOCUMENT;
  }
  
  if (['html', 'htm', 'css', 'svg', 'wasm', 'swf'].includes(ext)) {
    return FileCategory.WEB_CONTENT;
  }
  
  if (['sql', 'csv', 'db', 'sqlite', 'mdb'].includes(ext)) {
    return FileCategory.DATABASE;
  }
  
  if (['mp4', 'avi', 'mkv', 'mp3', 'wav', 'flac', 'ogg'].includes(ext)) {
    return FileCategory.MEDIA;
  }
  
  return FileCategory.UNKNOWN;
}

/**
 * Validate file based on its type
 */
async function validateFileByType(
  buffer: Buffer,
  fileType: FileTypeInfo
): Promise<{ threats: Threat[]; metadata: Partial<FileMetadata> }> {
  const ext = fileType.ext.toLowerCase();
  const mime = fileType.mime.toLowerCase();

  // PDF
  if (mime === 'application/pdf' || ext === 'pdf') {
    return validatePDF(buffer);
  }

  // Images
  if (mime === 'image/png' || ext === 'png') {
    return validatePNG(buffer);
  }
  if (mime === 'image/jpeg' || ext === 'jpg' || ext === 'jpeg') {
    return validateJPEG(buffer);
  }
  if (mime === 'image/gif' || ext === 'gif') {
    return validateGIF(buffer);
  }
  if (mime === 'image/svg+xml' || ext === 'svg') {
    return validateSVG(buffer);
  }
  if (mime === 'image/webp' || ext === 'webp') {
    return validateWebP(buffer);
  }

  // Archives
  if (mime === 'application/zip' || ext === 'zip') {
    return validateZIP(buffer);
  }
  if (mime === 'application/x-rar' || ext === 'rar') {
    return validateRAR(buffer);
  }
  if (mime === 'application/gzip' || ext === 'gz') {
    return validateGZIP(buffer);
  }
  if (mime === 'application/x-7z-compressed' || ext === '7z') {
    return validate7Z(buffer);
  }
  if (mime === 'application/x-tar' || ext === 'tar') {
    return validateTAR(buffer);
  }

  // Executables
  if (ext === 'exe' || ext === 'dll' || ext === 'msi') {
    return validatePE(buffer);
  }
  if (mime === 'application/x-executable' || mime === 'application/x-elf') {
    return validateELF(buffer);
  }

  // Scripts
  if (ext === 'js' || mime === 'application/javascript') {
    return validateScript(buffer, 'javascript');
  }
  if (ext === 'py') {
    return validateScript(buffer, 'python');
  }
  if (ext === 'sh') {
    return validateScript(buffer, 'bash');
  }
  if (ext === 'ps1') {
    return validateScript(buffer, 'powershell');
  }
  if (ext === 'vbs') {
    return validateScript(buffer, 'vbscript');
  }

  // Config files (but check for SVG first)
  if (ext === 'svg' || (mime.includes('xml') && buffer.toString('utf8', 0, 200).includes('<svg'))) {
    return validateSVG(buffer);
  }
  
  if (ext === 'json' || mime === 'application/json') {
    return validateConfigFile(buffer, 'json');
  }
  if (ext === 'yaml' || ext === 'yml') {
    return validateConfigFile(buffer, 'yaml');
  }
  if ((ext === 'xml' || mime === 'application/xml' || mime === 'text/xml') && ext !== 'svg') {
    return validateConfigFile(buffer, 'xml');
  }

  // Default: no specific validation
  return {
    threats: [],
    metadata: {
      signatureValid: true,
      checksPerformed: ['BasicValidation'],
      warnings: ['No specific validator for this file type'],
    },
  };
}

/**
 * Detect file type manually when file-type library fails
 */
function detectFileTypeManually(_buffer: Buffer, fileName?: string): FileTypeInfo | null {
  const ext = fileName?.split('.').pop()?.toLowerCase() || '';
  
  // SVG files
  if (ext === 'svg') {
    return {
      ext: 'svg',
      mime: 'image/svg+xml',
      category: FileCategory.WEB_CONTENT,
    };
  }
  
  // Text-based files
  if (['txt', 'log', 'md', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'sh'].includes(ext)) {
    return {
      ext,
      mime: `text/${ext}`,
      category: ['js', 'py', 'sh'].includes(ext) ? FileCategory.SCRIPT : FileCategory.UNKNOWN,
    };
  }
  
  return null;
}

/**
 * Perform universal security checks applicable to all files
 */
function performUniversalChecks(buffer: Buffer, result: ScanResult): void {
  if (!result.metadata) {
    result.metadata = {
      signatureValid: false,
      checksPerformed: [],
      warnings: [],
    };
  }

  // Null byte check
  if (buffer.includes('\x00') && result.fileType?.category === FileCategory.SCRIPT) {
    result.metadata.warnings!.push('Contains null bytes - unusual for text files');
  }

  // Very high entropy check (possible encryption/packing)
  const sampleSize = Math.min(buffer.length, 10000);
  let byteFreq = new Array(256).fill(0);
  for (let i = 0; i < sampleSize; i++) {
    byteFreq[buffer[i]]++;
  }
  
  let entropy = 0;
  for (const freq of byteFreq) {
    if (freq > 0) {
      const p = freq / sampleSize;
      entropy -= p * Math.log2(p);
    }
  }

  if (entropy > 7.8 && result.fileType?.category !== FileCategory.ARCHIVE) {
    result.metadata.warnings!.push(`Very high entropy (${entropy.toFixed(2)}/8) - possibly encrypted`);
  }
}

// Re-export types
export * from './types.js';

export default {
  scanFile,
};
