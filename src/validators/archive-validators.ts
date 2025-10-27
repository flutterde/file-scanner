/**
 * Archive file validators (ZIP, RAR, TAR, GZIP, 7Z)
 */
import { Threat, ThreatType, FileMetadata } from '../types.js';
import { bufferToHex } from '../utils/file-reader.js';
import path from 'path';

/**
 * Validate ZIP file
 */
export function validateZIP(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['ZIPSignatureValidation', 'ZipSlipCheck', 'CompressionRatioCheck'],
    warnings: [],
  };

  // ZIP local file header signature: PK\x03\x04 or PK\x05\x06 (empty archive)
  metadata.magicBytes = bufferToHex(buffer, 4);

  const validSignatures = [
    Buffer.from([0x50, 0x4B, 0x03, 0x04]), // Local file header
    Buffer.from([0x50, 0x4B, 0x05, 0x06]), // End of central directory
    Buffer.from([0x50, 0x4B, 0x07, 0x08]), // Spanning signature
  ];

  const hasValidSignature = validSignatures.some(sig => 
    buffer.subarray(0, 4).equals(sig)
  );

  if (!hasValidSignature) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid ZIP signature',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Parse ZIP entries for security checks
  let offset = 0;
  let entryCount = 0;
  let totalUncompressedSize = 0;
  let totalCompressedSize = 0;
  const filenames: string[] = [];

  while (offset < buffer.length - 30) {
    // Look for local file header
    if (buffer.readUInt32LE(offset) !== 0x04034b50) {
      offset++;
      continue;
    }

    entryCount++;
    if (entryCount > 10000) {
      threats.push({
        type: ThreatType.EXCESSIVE_SIZE,
        severity: 'high',
        description: `Excessive number of ZIP entries: ${entryCount}`,
      });
      break;
    }

    // Read entry data
    const compressedSize = buffer.readUInt32LE(offset + 18);
    const uncompressedSize = buffer.readUInt32LE(offset + 22);
    const filenameLength = buffer.readUInt16LE(offset + 26);
    const extraFieldLength = buffer.readUInt16LE(offset + 28);

    if (offset + 30 + filenameLength > buffer.length) {
      break;
    }

    const filename = buffer.subarray(offset + 30, offset + 30 + filenameLength).toString('utf8');
    filenames.push(filename);

    // Zip slip vulnerability check (path traversal)
    if (filename.includes('..') || path.isAbsolute(filename)) {
      threats.push({
        type: ThreatType.ZIP_SLIP,
        severity: 'critical',
        description: `ZIP slip vulnerability detected: ${filename}`,
        details: { filename },
      });
    }

    // Check for null bytes in filename
    if (filename.includes('\x00')) {
      threats.push({
        type: ThreatType.MALFORMED_STRUCTURE,
        severity: 'high',
        description: 'Null byte in ZIP filename',
        details: { filename },
      });
    }

    // Symlink detection (Unix attributes)
    const externalAttrs = buffer.readUInt32LE(offset + 38);
    const fileMode = (externalAttrs >> 16) & 0xFFFF;
    if ((fileMode & 0xA000) === 0xA000) { // S_IFLNK
      metadata.warnings!.push(`Symbolic link detected: ${filename}`);
    }

    totalCompressedSize += compressedSize;
    totalUncompressedSize += uncompressedSize;

    offset += 30 + filenameLength + extraFieldLength + compressedSize;
  }

  // Compression bomb detection
  if (totalCompressedSize > 0) {
    const compressionRatio = totalUncompressedSize / totalCompressedSize;
    metadata.compressionRatio = compressionRatio;

    if (compressionRatio > 100) {
      threats.push({
        type: ThreatType.COMPRESSION_BOMB,
        severity: 'critical',
        description: `Compression bomb detected - ratio: ${compressionRatio.toFixed(2)}:1`,
        details: {
          compressedSize: totalCompressedSize,
          uncompressedSize: totalUncompressedSize,
        },
      });
    } else if (compressionRatio > 50) {
      metadata.warnings!.push(`High compression ratio: ${compressionRatio.toFixed(2)}:1`);
    }
  }

  // Check for excessive total uncompressed size (>10GB)
  if (totalUncompressedSize > 10 * 1024 * 1024 * 1024) {
    threats.push({
      type: ThreatType.COMPRESSION_BOMB,
      severity: 'high',
      description: `Excessive uncompressed size: ${(totalUncompressedSize / 1024 / 1024 / 1024).toFixed(2)}GB`,
    });
  }

  // Nested archive detection
  const archiveExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'];
  const nestedArchives = filenames.filter(f => 
    archiveExtensions.some(ext => f.toLowerCase().endsWith(ext))
  );

  if (nestedArchives.length > 0) {
    metadata.warnings!.push(`Contains ${nestedArchives.length} nested archive(s)`);
  }

  return { threats, metadata };
}

/**
 * Validate RAR file
 */
export function validateRAR(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['RARSignatureValidation'],
    warnings: [],
  };

  // RAR signature: Rar!\x1A\x07 (RAR 4.x) or Rar!\x1A\x07\x01\x00 (RAR 5.0+)
  metadata.magicBytes = bufferToHex(buffer, 8);

  const rar4Signature = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
  const rar5Signature = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);

  if (!buffer.subarray(0, 7).equals(rar4Signature.subarray(0, 7)) &&
      !buffer.subarray(0, 8).equals(rar5Signature)) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid RAR signature',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Check for encrypted archive
  if (buffer.includes('CRYPT')) {
    metadata.warnings!.push('Archive appears to be encrypted');
  }

  return { threats, metadata };
}

/**
 * Validate GZIP file
 */
export function validateGZIP(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['GZIPSignatureValidation', 'HeaderValidation'],
    warnings: [],
  };

  // GZIP signature: 0x1F 0x8B
  metadata.magicBytes = bufferToHex(buffer, 4);

  if (buffer[0] !== 0x1F || buffer[1] !== 0x8B) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid GZIP signature',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Validate compression method (should be 8 for DEFLATE)
  if (buffer[2] !== 0x08) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'medium',
      description: `Invalid GZIP compression method: ${buffer[2]}`,
    });
  }

  return { threats, metadata };
}

/**
 * Validate 7Z file
 */
export function validate7Z(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['7ZSignatureValidation'],
    warnings: [],
  };

  // 7z signature: 37 7A BC AF 27 1C
  metadata.magicBytes = bufferToHex(buffer, 6);

  const signature7z = Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);

  if (!buffer.subarray(0, 6).equals(signature7z)) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid 7Z signature',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  return { threats, metadata };
}

/**
 * Validate TAR file
 */
export function validateTAR(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['TARHeaderValidation', 'ZipSlipCheck'],
    warnings: [],
  };

  // TAR has magic "ustar" at offset 257
  if (buffer.length < 512) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'critical',
      description: 'File too small to be valid TAR',
    });
    return { threats, metadata };
  }

  const tarMagic = buffer.subarray(257, 263).toString('ascii');
  metadata.magicBytes = bufferToHex(buffer.subarray(257, 263), 6);

  if (tarMagic !== 'ustar\x00' && tarMagic !== 'ustar ') {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'high',
      description: 'Missing TAR ustar magic bytes',
    });
  } else {
    metadata.signatureValid = true;
  }

  // Check filenames for path traversal
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const filename = buffer.subarray(offset, offset + 100).toString('ascii').replace(/\x00.*$/, '');
    
    if (!filename) {
      break; // End of archive
    }

    // Zip slip check
    if (filename.includes('..') || path.isAbsolute(filename)) {
      threats.push({
        type: ThreatType.ZIP_SLIP,
        severity: 'critical',
        description: `TAR slip vulnerability detected: ${filename}`,
        details: { filename },
      });
    }

    // Get file size
    const sizeOctal = buffer.subarray(offset + 124, offset + 136).toString('ascii').trim();
    const fileSize = parseInt(sizeOctal, 8) || 0;

    // Move to next header (512-byte aligned)
    offset += 512 + Math.ceil(fileSize / 512) * 512;
  }

  return { threats, metadata };
}
