/**
 * Example usage with Buffer API
 */
import { scanFile } from './dist/index.js';
import { readFileSync } from 'fs';

// Example 1: Scan from file system
async function scanFromFile() {
  console.log('Example 1: Scanning file from filesystem\n');
  
  const buffer = readFileSync('./test.js');
  const result = await scanFile(buffer, { fileName: 'test.js' });
  
  console.log(`File: ${result.fileName}`);
  console.log(`Size: ${result.fileSize} bytes`);
  console.log(`Clean: ${result.isClean ? '✓' : '✗'}`);
  console.log(`Threats: ${result.threats.length}\n`);
}

// Example 2: Scan from buffer directly (e.g., from HTTP upload)
async function scanFromBuffer() {
  console.log('Example 2: Scanning buffer directly\n');
  
  // Simulate uploaded file buffer
  const pdfContent = '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF';
  const buffer = Buffer.from(pdfContent);
  
  const result = await scanFile(buffer, { fileName: 'uploaded.pdf' });
  
  console.log(`File: ${result.fileName}`);
  console.log(`Type: ${result.fileType?.mime}`);
  console.log(`Clean: ${result.isClean ? '✓' : '✗'}`);
  console.log(`Signature Valid: ${result.metadata?.signatureValid}\n`);
}

// Example 3: Express.js file upload handler
function expressExample() {
  console.log('Example 3: Express.js integration\n');
  console.log(`
// With multer for file uploads
import multer from 'multer';
import express from 'express';
import { scanFile } from 'file-scanner';

const upload = multer({ storage: multer.memoryStorage() });
const app = express();

app.post('/upload', upload.single('file'), async (req, res) => {
  // req.file.buffer contains the file data
  const result = await scanFile(req.file.buffer, {
    fileName: req.file.originalname,
  });

  if (!result.isClean) {
    return res.status(400).json({
      error: 'Malicious file detected',
      threats: result.threats
    });
  }

  // File is safe, proceed
  res.json({ success: true });
});
  `);
}

// Run examples
async function main() {
  console.log('='.repeat(60));
  console.log('File Scanner - Buffer API Examples');
  console.log('='.repeat(60) + '\n');
  
  await scanFromFile();
  await scanFromBuffer();
  expressExample();
  
  console.log('='.repeat(60));
}

main().catch(console.error);
