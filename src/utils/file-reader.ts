/**
 * File reading utilities
 */
import fs from 'fs/promises';
import { createReadStream } from 'fs';

/**
 * Read file as buffer
 */
export async function readFileAsBuffer(filePath: string, maxSize?: number): Promise<Buffer> {
  const stats = await fs.stat(filePath);
  
  if (maxSize && stats.size > maxSize) {
    throw new Error(`File size (${stats.size}) exceeds maximum allowed size (${maxSize})`);
  }
  
  return fs.readFile(filePath);
}

/**
 * Read first N bytes of file
 */
export async function readFileHeader(filePath: string, bytes: number): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(bytes);
  const handle = await fs.open(filePath, 'r');
  
  try {
    await handle.read(buffer, 0, bytes, 0);
    return buffer;
  } finally {
    await handle.close();
  }
}

/**
 * Get file stats
 */
export async function getFileStats(filePath: string) {
  return fs.stat(filePath);
}

/**
 * Read file in chunks
 */
export async function* readFileInChunks(
  filePath: string,
  chunkSize: number = 64 * 1024
): AsyncGenerator<Buffer> {
  const stream = createReadStream(filePath, { highWaterMark: chunkSize });
  
  for await (const chunk of stream) {
    yield chunk as Buffer;
  }
}

/**
 * Convert buffer to hex string
 */
export function bufferToHex(buffer: Buffer, maxBytes: number = 16): string {
  return buffer.subarray(0, maxBytes).toString('hex').toUpperCase();
}

/**
 * Calculate Shannon entropy of data (0-8, higher = more random/compressed)
 */
export function calculateEntropy(buffer: Buffer): number {
  const frequencies = new Map<number, number>();
  
  for (const byte of buffer) {
    frequencies.set(byte, (frequencies.get(byte) || 0) + 1);
  }
  
  let entropy = 0;
  const len = buffer.length;
  
  for (const count of frequencies.values()) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

/**
 * Search for pattern in buffer
 */
export function searchPattern(buffer: Buffer, pattern: Buffer | string): number {
  const searchBuffer = typeof pattern === 'string' ? Buffer.from(pattern) : pattern;
  return buffer.indexOf(searchBuffer);
}

/**
 * Check if buffer contains any of the patterns
 */
export function containsAnyPattern(buffer: Buffer, patterns: Array<Buffer | string>): boolean {
  return patterns.some(pattern => searchPattern(buffer, pattern) !== -1);
}

/**
 * Extract string from buffer (handles different encodings)
 */
export function extractString(
  buffer: Buffer,
  encoding: BufferEncoding = 'utf8',
  start: number = 0,
  end?: number
): string {
  try {
    return buffer.subarray(start, end).toString(encoding);
  } catch {
    return '';
  }
}
