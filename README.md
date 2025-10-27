# file-scanner

A comprehensive npm package for scanning files and detecting potential security threats, malware, and malicious content across multiple file types.

## Features

### Core High-Risk File Type Support

#### PDF Documents
- ✅ Magic bytes verification (`%PDF-` header)
- ✅ EOF marker validation (`%%EOF`)
- ✅ Cross-reference table integrity
- ✅ Embedded JavaScript detection
- ✅ Malicious form actions detection
- ✅ Launch actions that execute system commands
- ✅ Object stream manipulation detection
- ✅ Digital signature validation readiness
- ✅ Version consistency checks

#### Image Files
**PNG:**
- ✅ PNG signature verification (89 50 4E 47 0D 0A 1A 0A)
- ✅ IHDR chunk validation
- ✅ CRC checksum verification
- ✅ Dimension sanity limits (memory exhaustion protection)
- ✅ Chunk ordering enforcement

**JPEG:**
- ✅ SOI/EOI marker validation (FF D8 / FF D9)
- ✅ EXIF metadata injection detection
- ✅ Segment length validation
- ✅ Buffer overflow protection

**WebP:**
- ✅ RIFF container validation
- ✅ Chunk size verification
- ✅ VP8/VP8L format validation

**GIF:**
- ✅ Signature validation (GIF87a/GIF89a)
- ✅ Logical screen descriptor checks
- ✅ Frame count limits (DoS protection)

**SVG:**
- ✅ XML well-formedness
- ✅ Script tag detection (XSS protection)
- ✅ Event handler detection
- ✅ External entity (XXE) detection
- ✅ Foreign object inspection

#### Archive Files
**ZIP:**
- ✅ Magic bytes verification
- ✅ Zip slip vulnerability detection (path traversal)
- ✅ Compression bomb detection
- ✅ Entry count limits
- ✅ Nested archive detection
- ✅ Null byte in filename detection

**RAR, GZIP, 7Z, TAR:**
- ✅ Format-specific signature validation
- ✅ Header integrity checks
- ✅ Path traversal protection

#### Executable Files
**Windows PE (EXE/DLL):**
- ✅ MZ signature validation
- ✅ PE header verification
- ✅ Entropy analysis (packed/encrypted detection)
- ✅ Digital signature checking

**Linux ELF:**
- ✅ ELF magic number validation
- ✅ Class and architecture validation
- ✅ Entropy analysis

#### Script Files
**JavaScript, Python, Bash, PowerShell, VBScript:**
- ✅ Dangerous function detection (`eval`, `exec`, etc.)
- ✅ Command injection pattern matching
- ✅ Base64/hex encoding detection
- ✅ Obfuscation indicators
- ✅ URL extraction

#### Configuration Files
**JSON, YAML, XML:**
- ✅ Syntax validation
- ✅ Prototype pollution detection (JSON)
- ✅ YAML tag injection detection
- ✅ XXE attack prevention (XML)
- ✅ Billion laughs attack detection
- ✅ Nesting depth limits

### Cross-Cutting Security Features
- ✅ File size validation
- ✅ MIME type consistency checks
- ✅ Magic byte verification
- ✅ Entropy analysis
- ✅ Character encoding validation
- ✅ Memory allocation boundaries

## Installation

```bash
npm install file-scanner
```

## Usage

### Basic Example

```typescript
import { scanFile } from 'file-scanner';
import { readFileSync } from 'fs';

// Read file as buffer
const buffer = readFileSync('/path/to/suspicious-file.pdf');
const result = await scanFile(buffer, { fileName: 'suspicious-file.pdf' });

console.log('Is Clean:', result.isClean);
console.log('Threats Found:', result.threats.length);
console.log('File Type:', result.fileType?.mime);

if (!result.isClean) {
  result.threats.forEach(threat => {
    console.log(`[${threat.severity}] ${threat.type}: ${threat.description}`);
  });
}
```

### Advanced Usage with Options

```typescript
import { scanFile, ScanOptions } from 'file-scanner';
import { readFileSync } from 'fs';

const buffer = readFileSync('/path/to/file.zip');

const options: ScanOptions = {
  fileName: 'archive.zip',
  maxFileSize: 100 * 1024 * 1024, // 100MB
  maxNestingDepth: 5,
  maxCompressionRatio: 50,
  deepScan: true,
};

const result = await scanFile(buffer, options);

// Access detailed metadata
console.log('Signature Valid:', result.metadata?.signatureValid);
console.log('Checks Performed:', result.metadata?.checksPerformed);
console.log('Warnings:', result.metadata?.warnings);
console.log('Compression Ratio:', result.metadata?.compressionRatio);
```

### Handling Results

```typescript
import { scanFile, ThreatType, FileCategory } from 'file-scanner';
import { readFileSync } from 'fs';

const buffer = readFileSync('/path/to/document.pdf');
const result = await scanFile(buffer, { fileName: 'document.pdf' });

// Check for specific threat types
const hasJavaScript = result.threats.some(
  t => t.type === ThreatType.EMBEDDED_JAVASCRIPT
);

// Filter by severity
const criticalThreats = result.threats.filter(
  t => t.severity === 'critical'
);

// Check file category
if (result.fileType?.category === FileCategory.EXECUTABLE) {
  console.warn('Executable file detected!');
}
```

## API Reference

### `scanFile(buffer: Buffer, options?: ScanOptions): Promise<ScanResult>`

Scans a file buffer for security threats.

**Parameters:**
- `buffer` (Buffer): File content as a Buffer
- `options` (ScanOptions, optional): Scanning configuration
  - `fileName` (string, optional): Original filename for reference
  - `maxFileSize` (number): Maximum allowed size in bytes
  - `deepScan` (boolean): Enable thorough scanning
  - `maxCompressionRatio` (number): For archives
  - Other options...

**Returns:** `Promise<ScanResult>`

### `ScanResult` Interface

```typescript
interface ScanResult {
  fileName: string;          // File name or 'buffer'
  isClean: boolean;          // Overall safety status
  threats: Threat[];         // Detected threats
  scannedAt: Date;          // Scan timestamp
  fileType?: FileTypeInfo;   // Detected file type
  fileSize: number;          // File size in bytes
  metadata?: FileMetadata;   // Additional information
}
```

### `Threat` Interface

```typescript
interface Threat {
  type: ThreatType;                    // Threat category
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;                 // Human-readable description
  location?: string;                   // Location in file
  details?: Record<string, unknown>;   // Additional context
}
```

### `ScanOptions` Interface

```typescript
interface ScanOptions {
  fileName?: string;            // Original filename (optional)
  maxFileSize?: number;         // Max bytes to scan (default: 500MB)
  maxNestingDepth?: number;     // Max archive nesting (default: unlimited)
  maxCompressionRatio?: number; // Max compression ratio (default: unlimited)
  deepScan?: boolean;           // Enable deep scanning (default: true)
  customPatterns?: RegExp[];    // Custom threat patterns
  skipChecks?: string[];        // Skip specific checks
}
```

## Threat Types

The package detects the following threat categories:

### PDF Threats
- `EMBEDDED_JAVASCRIPT` - JavaScript in PDFs
- `MALICIOUS_FORM_ACTION` - Suspicious form actions
- `LAUNCH_ACTION` - System command execution
- `OBJECT_STREAM_MANIPULATION` - PDF structure manipulation

### Image Threats
- `CHUNK_MANIPULATION` - PNG chunk tampering
- `BUFFER_OVERFLOW` - Malformed dimensions
- `POLYGLOT_FILE` - Dual-format files
- `METADATA_INJECTION` - EXIF payload injection

### Archive Threats
- `ZIP_SLIP` - Path traversal vulnerability
- `COMPRESSION_BOMB` - Decompression DoS
- `NESTED_ARCHIVE` - Excessive nesting

### Executable Threats
- `CODE_EXECUTION` - Executable detection
- `SUSPICIOUS_ENTROPY` - Packed/encrypted code
- `INVALID_SIGNATURE` - Missing/invalid signatures

### Script Threats
- `DANGEROUS_FUNCTION` - eval, exec, etc.
- `CODE_INJECTION` - Injection patterns
- `DESERIALIZATION_ATTACK` - Unsafe deserialization

### Web Content Threats
- `XSS_PAYLOAD` - Cross-site scripting
- `IFRAME_INJECTION` - Hidden iframes
- `FORM_HIJACKING` - Form manipulation

### Universal Threats
- `INVALID_MAGIC_BYTES` - Wrong file signature
- `MIME_MISMATCH` - Type/extension mismatch
- `EXCESSIVE_SIZE` - Unreasonably large files
- `MALFORMED_STRUCTURE` - Corrupted structure

## File Categories

Files are categorized into:
- `PDF` - PDF documents
- `IMAGE` - Image files (PNG, JPEG, GIF, SVG, WebP)
- `DOCUMENT` - Office documents (DOCX, XLSX, etc.)
- `ARCHIVE` - Compressed archives (ZIP, RAR, TAR, etc.)
- `EXECUTABLE` - Binary executables (EXE, DLL, ELF, etc.)
- `SCRIPT` - Script files (JS, Python, Bash, etc.)
- `WEB_CONTENT` - Web files (HTML, CSS, WASM, etc.)
- `DATABASE` - Database files (SQL, CSV, etc.)
- `MEDIA` - Media files (MP4, MP3, etc.)
- `UNKNOWN` - Unrecognized types

## Security Best Practices

1. **Always scan files before processing** - Especially user uploads
2. **Set appropriate size limits** - Prevent resource exhaustion
3. **Use deep scanning in production** - More thorough analysis
4. **Monitor critical threats** - Act on critical severity findings
5. **Validate MIME types** - Don't trust file extensions
6. **Log scan results** - Maintain audit trail
7. **Quarantine suspicious files** - Isolate threats immediately

## Performance Considerations

- Files are read into memory for analysis
- Large files (>100MB) may require increased memory
- Deep scanning adds ~20-30% overhead
- Archive scanning doesn't extract contents (metadata only)
- Entropy calculation samples first 100KB

## Limitations

- **Document macros:** Limited detection for Office macros (basic patterns only)
- **Encrypted archives:** Cannot inspect encrypted content
- **Polymorphic malware:** Signature-based detection only
- **Zero-day exploits:** No behavioral analysis
- **Binary analysis:** Basic PE/ELF validation, not full disassembly

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- New validators include comprehensive checks
- Documentation is updated
- Code follows TypeScript best practices

## License

ISC

## Author

otman

## Repository

[https://github.com/flutterde/file-scanner](https://github.com/flutterde/file-scanner)

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/flutterde/file-scanner/issues).


## Installation

```bash
npm install file-scanner
```

## Usage

```typescript
import { scanFile } from 'file-scanner';

const result = await scanFile('/path/to/file');
console.log(result);
```

## API

### `scanFile(filePath: string): Promise<ScanResult>`

Scans a file for potential malicious content.

**Parameters:**
- `filePath` - Path to the file to scan

**Returns:**
A promise that resolves to a `ScanResult` object containing:
- `filePath` - Path to the scanned file
- `isClean` - Whether the file is clean
- `threats` - Array of detected threats
- `scannedAt` - Timestamp of when the scan was performed

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Watch mode for development
npm run dev

# Clean build artifacts
npm run clean
```

## License

ISC
