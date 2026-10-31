export function gcd(a, b) {
  a = absBigInt(a);
  b = absBigInt(b);
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

export function isPrime(n) {
  if (n < 2n) return false;
  if (n === 2n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

export function modPow(base, exponent, modulus) {
  if (modulus <= 0n) throw new Error("modulus must be positive");
  if (exponent < 0n) throw new Error("exponent must be non-negative");
  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) result = (result * base) % modulus;
    exponent /= 2n;
    base = (base * base) % modulus;
  }
  return result;
}

export function modInverse(a, modulus) {
  const [g, x] = extendedGcd(a, modulus);
  if (g !== 1n) throw new Error("modular inverse does not exist");
  return ((x % modulus) + modulus) % modulus;
}

export function choosePublicExponent(phi) {
  const candidates = [3n, 5n, 17n, 257n, 65537n];
  for (const e of candidates) {
    if (e < phi && gcd(e, phi) === 1n) return e;
  }
  for (let e = 3n; e < phi; e += 2n) {
    if (gcd(e, phi) === 1n) return e;
  }
  throw new Error("공개 지수 e를 찾을 수 없습니다.");
}

export function createKeyPair(p, q) {
  if (p === q) throw new Error("p와 q는 서로 다른 소수여야 합니다.");
  if (!isPrime(p) || !isPrime(q)) throw new Error("p와 q에는 소수만 입력할 수 있습니다.");
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = choosePublicExponent(phi);
  const d = modInverse(e, phi);
  return { p, q, n, phi, e, d };
}

export function encryptNumber(message, key) {
  if (message < 0n || message >= key.n) {
    throw new Error(`입력 오류: 원문은 0 이상 ${key.n - 1n} 이하의 정수만 입력할 수 있습니다. (현재 n=${key.n})`);
  }
  return modPow(message, key.e, key.n);
}

export function decryptNumber(cipher, key) {
  if (cipher < 0n || cipher >= key.n) throw new Error(`암호문은 0 이상 ${key.n} 미만이어야 합니다.`);
  return modPow(cipher, key.d, key.n);
}

export function factorByTrialDivision(n) {
  if (n < 4n) throw new Error("4 이상의 합성수가 필요합니다.");
  let attempts = 0;
  attempts += 1;
  if (n % 2n === 0n) return { p: 2n, q: n / 2n, attempts };
  for (let divisor = 3n; divisor * divisor <= n; divisor += 2n) {
    attempts += 1;
    if (n % divisor === 0n) return { p: divisor, q: n / divisor, attempts };
  }
  throw new Error("두 수의 곱으로 분해하지 못했습니다.");
}

function extendedGcd(a, b) {
  if (b === 0n) return [absBigInt(a), a >= 0n ? 1n : -1n, 0n];
  const [g, x1, y1] = extendedGcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

function absBigInt(n) {
  return n < 0n ? -n : n;
}
