import { MAX_CHARACTERS, MAX_FILE_BYTES } from '../config.ts';

export type InputError = 'empty' | 'tooLong' | 'fileType' | 'fileSize' | 'fileEncoding' | 'fileRead' | 'emailSize' | 'emailRead';

export function characterCount(value: string): number {
  return Array.from(value).length;
}

export function validateText(value: string): InputError | undefined {
  if (characterCount(value) > MAX_CHARACTERS) return 'tooLong';
  if (!value.trim()) return 'empty';
  for (const character of value) {
    const code = character.charCodeAt(0);
    if ((code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127) return 'fileEncoding';
  }
}

export async function readTextFile(file: File): Promise<{ value: string } | { error: InputError }> {
  if (!/\.txt$/iu.test(file.name)) return { error: 'fileType' };
  if (file.size > MAX_FILE_BYTES) return { error: 'fileSize' };

  let bytes: ArrayBuffer;
  try {
    bytes = await file.arrayBuffer();
  } catch {
    return { error: 'fileRead' };
  }
  try {
    const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/\r\n?/gu, '\n');
    const error = validateText(value);
    return error ? { error } : { value };
  } catch {
    return { error: 'fileEncoding' };
  }
}
