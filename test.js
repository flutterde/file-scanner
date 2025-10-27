/**
 * Simple test to verify the file scanner works
 */
import { scanFile } from './dist/index.js';
import { writeFileSync, readFileSync } from 'fs';

// Create test files
function createTestFiles() {
  const testDir = './test-files';
  
  // Create a malicious PDF (simulated)
  const maliciousPDF = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('malicious');) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
trailer
<< /Size 4 /Root 1 0 R >>
%%EOF`;

  // Create a suspicious JavaScript file
  const maliciousJS = `
// Suspicious script
const data = "eval is dangerous";
eval(data);
const cmd = require('child_process');
cmd.exec('rm -rf /');
`;

  // Create an SVG with XSS
  const maliciousSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <script>alert('malicious')</script>
  <circle cx="50" cy="50" r="40" onclick="alert('click')"/>
</svg>`;

  // Create clean PNG (minimal valid PNG)
  const cleanPNG = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, // IHDR length
    0x49, 0x48, 0x44, 0x52, // "IHDR"
    0x00, 0x00, 0x00, 0x01, // Width: 1
    0x00, 0x00, 0x00, 0x01, // Height: 1
    0x08, 0x02, 0x00, 0x00, 0x00, // Bit depth, color type, etc.
    0x90, 0x77, 0x53, 0xDE, // CRC
    0x00, 0x00, 0x00, 0x00, // IEND length
    0x49, 0x45, 0x4E, 0x44, // "IEND"
    0xAE, 0x42, 0x60, 0x82, // CRC
  ]);

  try {
    writeFileSync('malicious.pdf', maliciousPDF);
    writeFileSync('malicious.js', maliciousJS);
    writeFileSync('malicious.svg', maliciousSVG);
    writeFileSync('clean.png', cleanPNG);
    
    console.log('✓ Test files created');
    return true;
  } catch (error) {
    console.error('Error creating test files:', error);
    return false;
  }
}

// Run tests
async function runTests() {
  console.log('File Scanner Test Suite\n');
  console.log('='.repeat(50));
  
  if (!createTestFiles()) {
    console.error('Failed to create test files');
    return;
  }
  
  const testFiles = [
    { path: 'malicious.pdf', expectedThreats: true, description: 'PDF with JavaScript' },
    { path: 'malicious.js', expectedThreats: true, description: 'JavaScript with dangerous functions' },
    { path: 'malicious.svg', expectedThreats: true, description: 'SVG with XSS payloads' },
    { path: 'clean.png', expectedThreats: false, description: 'Clean PNG image' },
  ];
  
  for (const test of testFiles) {
    console.log(`\n${test.description}`);
    console.log('-'.repeat(50));
    
    try {
      // Read file as buffer
      const buffer = readFileSync(test.path);
      const result = await scanFile(buffer, { fileName: test.path });
      
      console.log(`File: ${result.fileName}`);
      console.log(`Size: ${result.fileSize} bytes`);
      console.log(`Type: ${result.fileType?.mime || 'unknown'}`);
      console.log(`Clean: ${result.isClean ? '✓ Yes' : '✗ No'}`);
      console.log(`Threats: ${result.threats.length}`);
      
      if (result.threats.length > 0) {
        result.threats.forEach(threat => {
          console.log(`  - [${threat.severity.toUpperCase()}] ${threat.type}`);
          console.log(`    ${threat.description}`);
        });
      }
      
      if (result.metadata) {
        console.log(`Signature Valid: ${result.metadata.signatureValid}`);
        if (result.metadata.warnings.length > 0) {
          console.log(`Warnings: ${result.metadata.warnings.length}`);
        }
      }
      
      // Verify expectations
      const passed = test.expectedThreats ? !result.isClean : result.isClean;
      console.log(`\nTest Result: ${passed ? '✓ PASSED' : '✗ FAILED'}`);
      
      if (!passed) {
        console.log(`Expected threats: ${test.expectedThreats}, Got clean: ${result.isClean}`);
      }
      
    } catch (error) {
      console.error(`✗ Error: ${error.message}`);
    }
  }
  
  console.log('\n' + '='.repeat(50));
  console.log('Test suite completed\n');
}

runTests().catch(console.error);
