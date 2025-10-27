/**
 * PDF file validator
 */
import { Threat, ThreatType, FileMetadata } from '../types.js';
import { bufferToHex, containsAnyPattern } from '../utils/file-reader.js';

/**
 * Validate PDF file structure and detect threats
 */
export function validatePDF(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const checksPerformed: string[] = [];
  const warnings: string[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed,
    warnings,
  };

  // 1. Magic bytes verification: Must begin with %PDF- header
  const pdfHeader = buffer.subarray(0, 5).toString('ascii');
  metadata.magicBytes = bufferToHex(buffer, 8);
  checksPerformed.push('MagicBytesVerification');

  if (!pdfHeader.startsWith('%PDF-')) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid PDF magic bytes - file does not start with %PDF- header',
      location: 'Header',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // 2. Version declaration check
  const version = buffer.subarray(5, 8).toString('ascii');
  checksPerformed.push('VersionDeclaration');
  if (!/^[12]\.\d$/.test(version)) {
    warnings.push(`Unusual PDF version: ${version}`);
  }

  // 3. EOF marker validation
  const bufferStr = buffer.toString('binary');
  checksPerformed.push('EOFMarkerValidation');

  if (!bufferStr.includes('%%EOF')) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'high',
      description: 'Missing %%EOF terminator',
      location: 'End of file',
    });
  }

  // 4. Cross-reference table check (xref)
  checksPerformed.push('CrossReferenceTableCheck');
  if (!bufferStr.includes('xref') && !bufferStr.includes('/Type /XRef')) {
    warnings.push('Missing cross-reference table (xref)');
  }

  // 5. JavaScript detection (high risk)
  checksPerformed.push('JavaScriptDetection');
  const jsPatterns = ['/JavaScript', '/JS', '/AA', '/OpenAction', 'this.'];

  if (containsAnyPattern(buffer, jsPatterns)) {
    threats.push({
      type: ThreatType.EMBEDDED_JAVASCRIPT,
      severity: 'critical',
      description: 'Embedded JavaScript detected in PDF - potential code execution risk',
      details: { patterns: jsPatterns },
    });
  }

  // 6. Launch action detection (executes system commands)
  checksPerformed.push('LaunchActionDetection');
  if (bufferStr.includes('/Launch') || bufferStr.includes('/Action')) {
    threats.push({
      type: ThreatType.LAUNCH_ACTION,
      severity: 'critical',
      description: 'Launch action detected - may execute system commands',
      location: 'Action dictionary',
    });
  }

  // 7. Embedded file stream enumeration
  checksPerformed.push('EmbeddedFileDetection');
  if (bufferStr.includes('/EmbeddedFile') || bufferStr.includes('/EmbeddedFiles')) {
    warnings.push('Contains embedded files');
  }

  // 8. Form action validation
  checksPerformed.push('FormActionValidation');
  if (bufferStr.includes('/AcroForm') && (bufferStr.includes('/URI') || bufferStr.includes('/SubmitForm'))) {
    threats.push({
      type: ThreatType.MALICIOUS_FORM_ACTION,
      severity: 'high',
      description: 'PDF contains forms with external URI actions',
    });
  }

  // 9. Object stream manipulation detection
  checksPerformed.push('ObjectStreamCheck');
  const objStreamMatches = bufferStr.match(/\/ObjStm/g);
  if (objStreamMatches && objStreamMatches.length > 50) {
    warnings.push(`High number of object streams (${objStreamMatches.length}) - potential obfuscation`);
  }

  // 10. Suspicious encoding detection
  if (bufferStr.includes('/ASCIIHexDecode') || bufferStr.includes('/ASCII85Decode')) {
    warnings.push('Uses encoded streams - review content carefully');
  }

  return { threats, metadata };
}
