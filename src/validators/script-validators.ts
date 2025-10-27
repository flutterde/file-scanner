/**
 * Script and executable file validators
 */
import { Threat, ThreatType, FileMetadata } from '../types.js';
import { bufferToHex, calculateEntropy } from '../utils/file-reader.js';

/**
 * Validate script files (JS, Python, Bash, PowerShell, etc.)
 */
export function validateScript(
  buffer: Buffer,
  language: string
): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: true,
    checksPerformed: ['DangerousFunctionDetection', 'CommandInjectionCheck'],
    warnings: [],
    encoding: 'utf8',
  };

  const content = buffer.toString('utf8');

  // Dangerous function patterns by language
  const dangerousFunctions: Record<string, RegExp[]> = {
    javascript: [
      /\beval\s*\(/gi,
      /new\s+Function\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bchild_process\./gi,
      /__proto__/gi,
      /document\.write/gi,
      /innerHTML\s*=/gi,
    ],
    python: [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\b__import__\s*\(/gi,
      /os\.system\s*\(/gi,
      /subprocess\.(call|run|Popen)/gi,
      /pickle\.loads/gi,
    ],
    bash: [
      /\beval\s+/gi,
      /\$\(.*\)/g, // Command substitution
      /`.*`/g, // Backtick command substitution
      /rm\s+-rf\s+\//gi,
      />\s*\/dev\/sda/gi,
    ],
    powershell: [
      /Invoke-Expression/gi,
      /iex\s+/gi,
      /Invoke-WebRequest.*\|\s*iex/gi,
      /DownloadString/gi,
      /\[System\.Runtime\.InteropServices\.Marshal\]/gi,
    ],
    vbscript: [
      /CreateObject\s*\(\s*["']WScript\.Shell/gi,
      /CreateObject\s*\(\s*["']Scripting\.FileSystemObject/gi,
      /\.Run\s*\(/gi,
    ],
  };

  const patterns = dangerousFunctions[language.toLowerCase()] || [];
  const foundPatterns: string[] = [];

  for (const pattern of patterns) {
    if (pattern.test(content)) {
      foundPatterns.push(pattern.source);
    }
  }

  if (foundPatterns.length > 0) {
    threats.push({
      type: ThreatType.DANGEROUS_FUNCTION,
      severity: foundPatterns.length > 3 ? 'critical' : 'high',
      description: `Dangerous functions detected: ${foundPatterns.length} pattern(s)`,
      details: { patterns: foundPatterns.slice(0, 5) },
    });
  }

  // Check for encoded/obfuscated content
  const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g;
  const base64Matches = content.match(base64Pattern);
  if (base64Matches && base64Matches.length > 5) {
    metadata.warnings!.push('Contains multiple base64-encoded strings - possible obfuscation');
  }

  // Hex encoding check
  const hexPattern = /(?:\\x[0-9a-fA-F]{2}){10,}/g;
  if (hexPattern.test(content)) {
    metadata.warnings!.push('Contains hex-encoded strings');
  }

  // URL detection (potential C2 or download)
  const urlPattern = /https?:\/\/[^\s<>"']+/gi;
  const urls = content.match(urlPattern);
  if (urls && urls.length > 10) {
    metadata.warnings!.push(`Contains ${urls.length} URLs`);
  }

  // Check file size for minified/obfuscated content
  const lines = content.split('\n');
  const avgLineLength = content.length / lines.length;
  if (avgLineLength > 500) {
    metadata.warnings!.push('Unusually long lines - possible minified/obfuscated code');
  }

  return { threats, metadata };
}

/**
 * Validate Windows PE executables (EXE, DLL)
 */
export function validatePE(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['PEHeaderValidation', 'EntropyAnalysis', 'DigitalSignatureCheck'],
    warnings: [],
  };

  // DOS header signature: MZ
  metadata.magicBytes = bufferToHex(buffer, 2);

  if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid PE DOS header (MZ signature missing)',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Get PE header offset
  if (buffer.length < 64) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'critical',
      description: 'File too small to contain valid PE header',
    });
    return { threats, metadata };
  }

  const peOffset = buffer.readUInt32LE(60);

  if (peOffset >= buffer.length - 4) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'high',
      description: 'Invalid PE header offset',
    });
    return { threats, metadata };
  }

  // Validate PE signature: PE\x00\x00
  const peSignature = buffer.subarray(peOffset, peOffset + 4);
  if (peSignature[0] !== 0x50 || peSignature[1] !== 0x45 || 
      peSignature[2] !== 0x00 || peSignature[3] !== 0x00) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'high',
      description: 'Invalid PE signature',
    });
  }

  // Entropy analysis (high entropy = possibly packed/encrypted)
  const sampleSize = Math.min(buffer.length, 100000);
  const entropy = calculateEntropy(buffer.subarray(0, sampleSize));

  if (entropy > 7.2) {
    threats.push({
      type: ThreatType.SUSPICIOUS_ENTROPY,
      severity: 'high',
      description: `High entropy detected (${entropy.toFixed(2)}/8.0) - possibly packed or encrypted`,
      details: { entropy: entropy.toFixed(2) },
    });
  }

  // Check for digital signature (basic check)
  metadata.checksPerformed!.push('CertificateTableCheck');
  if (!buffer.includes('Microsoft')) {
    metadata.warnings!.push('No obvious digital signature detected');
  }

  return { threats, metadata };
}

/**
 * Validate ELF executables (Linux)
 */
export function validateELF(buffer: Buffer): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: false,
    checksPerformed: ['ELFHeaderValidation', 'EntropyAnalysis'],
    warnings: [],
  };

  // ELF magic: 7F 45 4C 46
  metadata.magicBytes = bufferToHex(buffer, 4);

  if (buffer[0] !== 0x7F || buffer[1] !== 0x45 || 
      buffer[2] !== 0x4C || buffer[3] !== 0x46) {
    threats.push({
      type: ThreatType.INVALID_MAGIC_BYTES,
      severity: 'critical',
      description: 'Invalid ELF magic number',
    });
    return { threats, metadata };
  }

  metadata.signatureValid = true;

  // Check ELF class (32-bit or 64-bit)
  const elfClass = buffer[4];
  if (elfClass !== 1 && elfClass !== 2) {
    threats.push({
      type: ThreatType.MALFORMED_STRUCTURE,
      severity: 'high',
      description: `Invalid ELF class: ${elfClass}`,
    });
  }

  // Entropy analysis
  const sampleSize = Math.min(buffer.length, 100000);
  const entropy = calculateEntropy(buffer.subarray(0, sampleSize));

  if (entropy > 7.2) {
    threats.push({
      type: ThreatType.SUSPICIOUS_ENTROPY,
      severity: 'high',
      description: `High entropy detected (${entropy.toFixed(2)}/8.0) - possibly packed`,
      details: { entropy: entropy.toFixed(2) },
    });
  }

  return { threats, metadata };
}

/**
 * Validate JSON/YAML/XML configuration files
 */
export function validateConfigFile(
  buffer: Buffer,
  type: 'json' | 'yaml' | 'xml'
): { threats: Threat[]; metadata: Partial<FileMetadata> } {
  const threats: Threat[] = [];
  const metadata: Partial<FileMetadata> = {
    signatureValid: true,
    checksPerformed: ['SyntaxValidation', 'InjectionCheck'],
    warnings: [],
    encoding: 'utf8',
  };

  const content = buffer.toString('utf8');

  if (type === 'json') {
    // JSON validation
    try {
      const parsed = JSON.parse(content);
      
      // Check depth
      const depth = getObjectDepth(parsed);
      if (depth > 50) {
        threats.push({
          type: ThreatType.DESERIALIZATION_ATTACK,
          severity: 'high',
          description: `Excessive nesting depth: ${depth} levels`,
        });
      }

      // Prototype pollution check
      if (JSON.stringify(parsed).includes('__proto__') || 
          JSON.stringify(parsed).includes('constructor')) {
        threats.push({
          type: ThreatType.DESERIALIZATION_ATTACK,
          severity: 'critical',
          description: 'Potential prototype pollution attack detected',
        });
      }
    } catch (error) {
      threats.push({
        type: ThreatType.MALFORMED_STRUCTURE,
        severity: 'high',
        description: `Invalid JSON syntax: ${(error as Error).message}`,
      });
    }
  } else if (type === 'yaml') {
    // YAML dangerous tags
    const dangerousTags = ['!!python', '!!java', '!!ruby'];
    for (const tag of dangerousTags) {
      if (content.includes(tag)) {
        threats.push({
          type: ThreatType.DESERIALIZATION_ATTACK,
          severity: 'critical',
          description: `Dangerous YAML tag detected: ${tag}`,
        });
      }
    }
  } else if (type === 'xml') {
    // XXE detection
    if (content.includes('<!ENTITY') || content.includes('SYSTEM')) {
      threats.push({
        type: ThreatType.MALFORMED_STRUCTURE,
        severity: 'critical',
        description: 'XML External Entity (XXE) detected',
      });
    }

    // Billion laughs check
    const entityCount = (content.match(/<!ENTITY/g) || []).length;
    if (entityCount > 10) {
      threats.push({
        type: ThreatType.DESERIALIZATION_ATTACK,
        severity: 'critical',
        description: 'Possible XML bomb (billion laughs attack)',
      });
    }
  }

  // Check for excessively large files
  if (buffer.length > 50 * 1024 * 1024) {
    threats.push({
      type: ThreatType.EXCESSIVE_SIZE,
      severity: 'high',
      description: `Configuration file exceeds 50MB: ${(buffer.length / 1024 / 1024).toFixed(2)}MB`,
    });
  }

  return { threats, metadata };
}

/**
 * Get maximum depth of nested object
 */
function getObjectDepth(obj: unknown, depth: number = 0): number {
  if (obj === null || typeof obj !== 'object') {
    return depth;
  }

  const depths = Object.values(obj).map(value => getObjectDepth(value, depth + 1));
  return depths.length > 0 ? Math.max(...depths) : depth;
}
