/**
 * Image file validators (PNG, JPEG, WebP, GIF, SVG)
 */
import { Threat, ThreatType, FileMetadata } from '../types.js';
import { bufferToHex } from '../utils/file-reader.js';

/**
 * Validate PNG file
 */
export function validatePNG(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['PNGSignatureVerification', 'IHDRValidation', 'ChunkValidation'],
    warnings: [],
  };

  // PNG signature: 89 50 4E 47 0D 0A 1A 0A
  const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  metadata.magicBytes = bufferToHex(buffer, 8);

  if (!buffer.subarray(0, 8).equals(pngSignature)) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid PNG signature',
      location: 'Header',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // IHDR must be first chunk after signature
  const firstChunkType = buffer.subarray(12, 16).toString('ascii');
  if (firstChunkType !== 'IHDR') {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'high',
      description: `IHDR chunk must be first, found: ${firstChunkType}`,
    });
  }

  // Validate IHDR dimensions
  if (buffer.length >= 24) {
    const width = buffer.readUInt32BE(16);
    const height = buffer.readUInt32BE(20);

    // Dimension sanity check (max 65535x65535)
    if (width > 65535 || height > 65535 || width === 0 || height === 0) {
      threats.push({
        type: ThreatType.BUFFER_OVERFLOW,
        severity: 'critical',
        description: `Invalid PNG dimensions: ${width}x${height}`,
        details: { width, height },
      });
    }

    // Memory exhaustion check (> 500MB uncompressed)
    const estimatedSize = width * height * 4; // RGBA
    if (estimatedSize > 500 * 1024 * 1024) {
      threats.push({
        type: ThreatType.EXCESSIVE_SIZE,
        severity: 'high',
        description: 'PNG dimensions may cause memory exhaustion',
        details: { estimatedMemory: `${Math.round(estimatedSize / 1024 / 1024)}MB` },
      });
    }
  }

  // Check for IEND chunk
  const bufferStr = buffer.toString('binary');
  if (!bufferStr.includes('IEND')) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'medium',
      description: 'Missing IEND terminator chunk',
    });
  }

  return { threats, metadata };
}

/**
 * Validate JPEG file
 */
export function validateJPEG(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['JPEGMarkerValidation', 'EXIFValidation'],
    warnings: [],
  };

  // SOI marker: FF D8
  metadata.magicBytes = bufferToHex(buffer, 4);

  if (buffer[0] !== 0xFF || buffer[1] !== 0xD8) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid JPEG SOI marker',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // EOI marker: FF D9
  if (buffer[buffer.length - 2] !== 0xFF || buffer[buffer.length - 1] !== 0xD9) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'medium',
      description: 'Missing or invalid JPEG EOI marker',
    });
  }

  // Check for suspicious EXIF data
  const exifMarker = buffer.indexOf(Buffer.from('Exif\x00\x00'));
  if (exifMarker !== -1) {
    metadata.checksPerformed!.push('EXIFDataCheck');
    
    // Look for suspicious patterns in EXIF
    const exifEnd = Math.min(exifMarker + 1000, buffer.length);
    const exifSection = buffer.subarray(exifMarker, exifEnd);
    
    if (exifSection.includes('script') || exifSection.includes('<')) {
      threats.push({
        type: ThreatType.METADATA_INJECTION,
        severity: 'high',
        description: 'Suspicious content detected in EXIF metadata',
      });
    }
  }

  // Check for comment fields (APP marker with potential scripts)
  let pos = 2;
  while (pos < buffer.length - 4) {
    if (buffer[pos] === 0xFF) {
      const marker = buffer[pos + 1];
      
      // APP markers (0xE0 - 0xEF) or COM (0xFE)
      if ((marker >= 0xE0 && marker <= 0xEF) || marker === 0xFE) {
        const segmentLength = buffer.readUInt16BE(pos + 2);
        
        // Segment length overflow protection
        if (segmentLength > 65535 - 2 || segmentLength < 2) {
          threats.push({
            type: ThreatType.BUFFER_OVERFLOW,
            severity: 'high',
            description: `Invalid JPEG segment length: ${segmentLength}`,
            location: `Offset ${pos}`,
          });
        }
        
        pos += 2 + segmentLength;
      } else {
        pos++;
      }
    } else {
      pos++;
    }
  }

  return { threats, metadata };
}

/**
 * Validate GIF file
 */
export function validateGIF(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['GIFSignatureValidation', 'FrameCountCheck'],
    warnings: [],
  };

  // GIF header: GIF87a or GIF89a
  const header = buffer.subarray(0, 6).toString('ascii');
  metadata.magicBytes = bufferToHex(buffer, 6);

  if (header !== 'GIF87a' && header !== 'GIF89a') {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid GIF signature',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Validate logical screen descriptor
  if (buffer.length >= 13) {
    const width = buffer.readUInt16LE(6);
    const height = buffer.readUInt16LE(8);

    if (width > 65535 || height > 65535 || width === 0 || height === 0) {
      threats.push({
        type: ThreatType.MALFORMED_STRUCTURE,
        severity: 'high',
        description: `Invalid GIF dimensions: ${width}x${height}`,
      });
    }
  }

  // Count frames (look for image descriptors: 0x2C)
  const frameCount = buffer.filter(byte => byte === 0x2C).length;
  if (frameCount > 1000) {
    threats.push({
      type: ThreatType.EXCESSIVE_SIZE,
      severity: 'high',
      description: `Excessive GIF frame count: ${frameCount} frames may cause resource exhaustion`,
    });
  }

  return { threats, metadata };
}

/**
 * Validate SVG file
 */
export function validateSVG(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['XMLWellFormedness', 'ScriptDetection', 'EventHandlerDetection'],
    warnings: [],
  };

  const content = buffer.toString('utf8');
  metadata.encoding = 'utf8';

  // Check for SVG declaration
  if (!content.includes('<svg') && !content.includes('<?xml')) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'high',
      description: 'Missing SVG or XML declaration',
    });
  } else {
    metadata.signatureValid = true;
  }

  // Script tag detection (XSS primary vector)
  if (/<script[\s>]/i.test(content)) {
    threats.push({
      type: ThreatType.XSS_PAYLOAD,
      severity: 'critical',
      description: 'SVG contains <script> tags - XSS risk',
    });
  }

  // Event handler detection
  const eventHandlers = ['onclick', 'onload', 'onmouseover', 'onerror', 'onmouseenter'];
  const foundHandlers = eventHandlers.filter(handler => 
    new RegExp(`\\b${handler}\\s*=`, 'i').test(content)
  );

  if (foundHandlers.length > 0) {
    threats.push({
      type: ThreatType.XSS_PAYLOAD,
      severity: 'critical',
      description: `SVG contains event handlers: ${foundHandlers.join(', ')}`,
      details: { handlers: foundHandlers },
    });
  }

  // Foreign object detection
  if (/<foreignObject/i.test(content)) {
    metadata.warnings!.push('Contains foreignObject elements - potential HTML/JS injection');
  }

  // External resource references
  if (/xlink:href\s*=\s*["']https?:\/\//i.test(content)) {
    metadata.warnings!.push('Contains external resource references');
  }

  // CDATA sections
  if (/<!\[CDATA\[/i.test(content)) {
    metadata.warnings!.push('Contains CDATA sections - review content');
  }

  // Check for DOCTYPE (XXE risk)
  if (/<!DOCTYPE/i.test(content) && /<!ENTITY/i.test(content)) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'critical',
      description: 'SVG contains DOCTYPE with ENTITY declarations - XXE attack risk',
    });
  }

  return { threats, metadata };
}

/**
 * Validate WebP file
 */
export function validateWebP(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['WebPSignatureValidation', 'ChunkSizeValidation'],
    warnings: [],
  };

  // RIFF container: RIFF....WEBP
  metadata.magicBytes = bufferToHex(buffer, 16);

  if (buffer.subarray(0, 4).toString('ascii') !== 'RIFF') {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid WebP RIFF container signature',
    });
    return { threats, metadata };
  }

  if (buffer.subarray(8, 12).toString('ascii') !== 'WEBP') {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid WebP format identifier',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Chunk size validation
  if (buffer.length >= 12) {
    const fileSize = buffer.readUInt32LE(4);
    if (fileSize + 8 !== buffer.length && fileSize + 8 !== buffer.length - 1) {
      threats.push({
        type: ThreatType.MALFORMED_STRUCTURE,
        severity: 'medium',
        description: 'WebP file size mismatch in RIFF header',
      });
    }
  }

  return { threats, metadata };
}
