// Display names for files: control characters, bidi overrides and bidi
// isolates are stripped, the fake.jpg.exe direction trick lives there, and
// the length caps at 200 runes.

/* eslint-disable no-control-regex -- stripping control characters is the whole point of this sanitiser */
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f\u202a-\u202e\u200e\u200f\u2066-\u2069\u061c]/g
/* eslint-enable no-control-regex */

export function safeName(name: string): string {
  const stripped = name.replace(UNSAFE_NAME_CHARS, '')
  return Array.from(stripped).slice(0, 200).join('') || 'file'
}
