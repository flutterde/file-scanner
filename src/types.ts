/**
 * Type definitions for file-scanner
 * @packageDocumentation
 */

/**
 * Result of a file scan
 */
export interface ScanResult {
  /** Name of the file (optional) */
  fileName: string;
  /** Whether the file is clean */
  isClean: boolean;
  /** List of detected threats */
  threats: Threat[];
  /** Timestamp of when the scan was performed */
  scannedAt: Date;
  /** Detected file type */
  fileType?: FileTypeInfo;
  /** File size in bytes */
  fileSize: number;
  /** Additional metadata */
  metadata?: FileMetadata;
}

/**
 * Represents a detected threat
 */
export interface Threat {
  /** Type of threat detected */
  type: ThreatType;
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description of the threat */
  description: string;
  /** Location in file where threat was detected */
  location?: string;
  /** Additional context */
  details?: Record<string, unknown>;
}

/**
 * File type information
 */
export interface FileTypeInfo {
  /** File extension */
  ext: string;
  /** MIME type */
  mime: string;
  /** Category of file */
  category: FileCategory;
}

/**
 * File metadata
 */
export interface FileMetadata {
  /** Magic bytes detected */
  magicBytes?: string;
  /** File signature valid */
  signatureValid: boolean;
  /** Detected encoding */
  encoding?: string;
  /** Compression ratio (for archives) */
  compressionRatio?: number;
  /** Additional checks performed */
  checksPerformed: string[];
  /** Warnings (non-critical issues) */
  warnings: string[];
}

/**
 * File category enumeration
 */
export enum FileCategory {
  PDF = 'PDF',
  IMAGE = 'Image',
  DOCUMENT = 'Document',
  ARCHIVE = 'Archive',
  EXECUTABLE = 'Executable',
  SCRIPT = 'Script',
  WEB_CONTENT = 'WebContent',
  DATABASE = 'Database',
  MEDIA = 'Media',
  UNKNOWN = 'Unknown',
}

/**
 * Threat type enumeration
 */
export enum ThreatType {
  // PDF threats
  EMBEDDED_JAVASCRIPT = 'EmbeddedJavaScript',
  MALICIOUS_FORM_ACTION = 'MaliciousFormAction',
  OBJECT_STREAM_MANIPULATION = 'ObjectStreamManipulation',
  LAUNCH_ACTION = 'LaunchAction',
  
  // Image threats
  CHUNK_MANIPULATION = 'ChunkManipulation',
  BUFFER_OVERFLOW = 'BufferOverflow',
  POLYGLOT_FILE = 'PolyglotFile',
  METADATA_INJECTION = 'MetadataInjection',
  
  // Document threats
  MACRO_PAYLOAD = 'MacroPayload',
  DDE_EXPLOITATION = 'DDEExploitation',
  EXTERNAL_TEMPLATE = 'ExternalTemplate',
  XML_BOMB = 'XMLBomb',
  
  // Archive threats
  ZIP_SLIP = 'ZipSlip',
  COMPRESSION_BOMB = 'CompressionBomb',
  NESTED_ARCHIVE = 'NestedArchive',
  
  // Executable threats
  CODE_EXECUTION = 'CodeExecution',
  INVALID_SIGNATURE = 'InvalidSignature',
  SUSPICIOUS_ENTROPY = 'SuspiciousEntropy',
  
  // Script threats
  DANGEROUS_FUNCTION = 'DangerousFunction',
  CODE_INJECTION = 'CodeInjection',
  DESERIALIZATION_ATTACK = 'DeserializationAttack',
  
  // Web content threats
  XSS_PAYLOAD = 'XSSPayload',
  IFRAME_INJECTION = 'IframeInjection',
  FORM_HIJACKING = 'FormHijacking',
  
  // Database threats
  SQL_INJECTION = 'SQLInjection',
  CSV_INJECTION = 'CSVInjection',
  
  // Media threats
  CODEC_EXPLOIT = 'CodecExploit',
  METADATA_OVERFLOW = 'MetadataOverflow',
  
  // Universal threats
  INVALID_MAGIC_BYTES = 'InvalidMagicBytes',
  MIME_MISMATCH = 'MimeMismatch',
  EXCESSIVE_SIZE = 'ExcessiveSize',
  MALFORMED_STRUCTURE = 'MalformedStructure',
  SUSPICIOUS_CONTENT = 'SuspiciousContent',
}

/**
 * Scanner options
 */
export interface ScanOptions {
  /** Optional file name for reference */
  fileName?: string;
  /** Maximum file size to scan (in bytes) */
  maxFileSize?: number;
  /** Maximum nesting depth for archives */
  maxNestingDepth?: number;
  /** Maximum compression ratio allowed */
  maxCompressionRatio?: number;
  /** Enable deep content scanning */
  deepScan?: boolean;
  /** Custom threat patterns */
  customPatterns?: RegExp[];
  /** Skip certain checks */
  skipChecks?: string[];
}
