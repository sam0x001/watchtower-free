// src/utils/punycode.ts
// Minimal punycode (RFC 3492) — needed because Cloudflare Workers' runtime may
// not expose the `url` module's host-parsing helpers for IDN. This is a
// self-contained port of the reference algorithm.

const PUNY_BASE = 36;
const PUNY_TMIN = 1;
const PUNY_TMAX = 26;
const PUNY_SKEW = 38;
const PUNY_DAMP = 700;
const PUNY_INITIAL_BIAS = 72;
const PUNY_INITIAL_N = 128;
const PUNY_DELIMITER = "-";

function adapt(delta: number, numpoints: number, first: boolean): number {
  delta = first ? Math.floor(delta / PUNY_DAMP) : delta >> 1;
  delta += Math.floor(delta / numpoints);
  let k = 0;
  while (delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1) {
    delta = Math.floor(delta / (PUNY_BASE - PUNY_TMIN));
    k += PUNY_BASE;
  }
  return k + Math.floor((PUNY_BASE - PUNY_TMIN + 1) * delta / (delta + PUNY_SKEW));
}

function digitToChar(d: number): string {
  return String.fromCharCode(d < 26 ? 97 + d : 22 + d);
}

function charToDigit(c: string): number {
  const code = c.charCodeAt(0);
  if (code >= 48 && code <= 57) return code - 22;
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  throw new Error(`Invalid punycode digit: ${c}`);
}

export function punycodeEncode(input: string): string {
  const codepoints: number[] = [];
  for (const ch of input) codepoints.push(ch.codePointAt(0)!);

  let output = "";
  for (const cp of codepoints) {
    if (cp < 128) output += String.fromCharCode(cp);
  }
  const basicCount = output.length;
  if (basicCount === codepoints.length) return output;

  let n = PUNY_INITIAL_N;
  let delta = 0;
  let bias = PUNY_INITIAL_BIAS;
  const handled = basicCount;
  const total = codepoints.length;

  let basicHandled = basicCount > 0;
  let h = handled;
  while (h < total) {
    const nextCp = Math.min(...codepoints.filter((c) => c >= n));
    delta += (nextCp - n) * (h + 1);
    n = nextCp;
    for (const cp of codepoints) {
      if (cp < n) delta++;
      if (cp === n) {
        let q = delta;
        for (let k = PUNY_BASE; ; k += PUNY_BASE) {
          const t = k <= bias ? PUNY_TMIN : k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
          if (q < t) break;
          output += digitToChar(t + ((q - t) % (PUNY_BASE - t)));
          q = Math.floor((q - t) / (PUNY_BASE - t));
        }
        output += digitToChar(q);
        bias = adapt(delta, h + 1, h === basicCount);
        delta = 0;
        h++;
      }
    }
    basicHandled = false;
    delta++;
    n++;
  }
  return "xn--" + output;
}

export function punydecode(input: string): string {
  const parts = input.split(PUNY_DELIMITER);
  const basic = parts.length > 1 ? parts.slice(0, -1).join(PUNY_DELIMITER) : "";
  let extended = parts.length > 1 ? parts[parts.length - 1] : input;

  let output = "";
  for (const ch of basic) {
    const cp = ch.codePointAt(0)!;
    if (cp < 128) output += ch;
    else throw new Error("Non-basic codepoint in basic portion");
  }
  if (!extended) return output;

  let n = PUNY_INITIAL_N;
  let bias = PUNY_INITIAL_BIAS;
  let i = 0;
  let pos = 0;
  while (extended.length > 0) {
    const oldi = i;
    let w = 1;
    for (let k = PUNY_BASE; ; k += PUNY_BASE) {
      if (extended.length === 0) throw new Error("Malformed punycode");
      const ch = extended[0]!;
      extended = extended.slice(1);
      const digit = charToDigit(ch);
      i += digit * w;
      const t = k <= bias ? PUNY_TMIN : k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
      if (digit < t) break;
      w *= PUNY_BASE - t;
    }
    pos++;
    bias = adapt(i - oldi, pos, oldi === 0);
    n += Math.floor(i / pos);
    i %= pos;
    output = output.slice(0, i) + String.fromCodePoint(n) + output.slice(i);
    i++;
  }
  return output;
}

export function punyDecode(input: string): string {
  // Decode a full domain — only labels starting with xn-- are decoded.
  return input
    .split(".")
    .map((label) => (label.toLowerCase().startsWith("xn--") ? punydecode(label.slice(4)) : label))
    .join(".");
}

export function punycodeDecode(input: string): string {
  return punyDecode(input);
}
