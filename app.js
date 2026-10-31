// RSA calculation functions are included in this file so that the website
// also works when index.html is opened directly with file://.
function gcd(a, b) {
  a = absBigInt(a);
  b = absBigInt(b);
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

function isPrime(n) {
  if (n < 2n) return false;
  if (n === 2n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

function modPow(base, exponent, modulus) {
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

function modInverse(a, modulus) {
  const [g, x] = extendedGcd(a, modulus);
  if (g !== 1n) throw new Error("modular inverse does not exist");
  return ((x % modulus) + modulus) % modulus;
}

function choosePublicExponent(phi) {
  const candidates = [3n, 5n, 17n, 257n, 65537n];
  for (const e of candidates) {
    if (e < phi && gcd(e, phi) === 1n) return e;
  }
  for (let e = 3n; e < phi; e += 2n) {
    if (gcd(e, phi) === 1n) return e;
  }
  throw new Error("공개 지수 e를 찾을 수 없습니다.");
}

function createKeyPair(p, q) {
  if (p === q) throw new Error("p와 q는 서로 다른 소수여야 합니다.");
  if (!isPrime(p) || !isPrime(q)) throw new Error("p와 q에는 소수만 입력할 수 있습니다.");
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = choosePublicExponent(phi);
  const d = modInverse(e, phi);
  return { p, q, n, phi, e, d };
}

function encryptNumber(message, key) {
  if (message < 0n || message >= key.n) {
    throw new Error(`입력 오류: 원문은 0 이상 ${key.n - 1n} 이하의 정수만 입력할 수 있습니다. (현재 n=${key.n})`);
  }
  return modPow(message, key.e, key.n);
}

function decryptNumber(cipher, key) {
  if (cipher < 0n || cipher >= key.n) throw new Error(`암호문은 0 이상 ${key.n} 미만이어야 합니다.`);
  return modPow(cipher, key.d, key.n);
}

function factorByTrialDivision(n) {
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

const $ = (id) => document.getElementById(id);

let currentKey = null;
let currentCipher = null;

const elements = {
  p: $("pInput"), q: $("qInput"), generate: $("generateBtn"), showPrimes: $("showPrimesBtn"),
  keyMessage: $("keyMessage"), keyResults: $("keyResults"), n: $("nResult"), phi: $("phiResult"),
  publicKey: $("publicResult"), privateKey: $("privateResult"), keyCalculation: $("keyCalculation"),
  message: $("messageInput"), encrypt: $("encryptBtn"), encryptMessage: $("encryptMessage"),
  encryptResult: $("encryptResult"), cipherValue: $("cipherValue"), encryptFormula: $("encryptFormula"),
  cipher: $("cipherInput"), decrypt: $("decryptBtn"), decryptMessage: $("decryptMessage"),
  decryptResult: $("decryptResult"), plainValue: $("plainValue"), decryptFormula: $("decryptFormula"),
  processExplanation: $("processExplanation"), processSummary: $("processSummary"),
  attackN: $("attackN"), attackE: $("attackE"), attackC: $("attackC"), attack: $("attackBtn"),
  attackMessage: $("attackMessage"), attackOutput: $("attackOutput"), factorResult: $("factorResult"),
  attemptResult: $("attemptResult"), crackedKeyResult: $("crackedKeyResult"), recoveredResult: $("recoveredResult"),
  experiment: $("runExperimentBtn"), experimentWrap: $("experimentWrap"), experimentBody: $("experimentBody"),
  toast: $("toast"), step1: $("stepMark1"), step2: $("stepMark2"), step3: $("stepMark3"),
  primeModal: $("primeModal"), primeList: $("primeList"), closePrimeModal: $("closePrimeModalBtn")
};

elements.generate.addEventListener("click", generateKeys);
elements.showPrimes.addEventListener("click", openPrimeList);
elements.closePrimeModal.addEventListener("click", closePrimeList);
elements.primeModal.addEventListener("click", (event) => {
  if (event.target === elements.primeModal) closePrimeList();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !elements.primeModal.hidden) closePrimeList();
});
elements.encrypt.addEventListener("click", encryptMessage);
elements.decrypt.addEventListener("click", decryptMessage);
elements.attack.addEventListener("click", runAttack);
elements.experiment.addEventListener("click", runExperiment);
elements.cipher.addEventListener("input", () => {
  if (currentKey) elements.decrypt.disabled = elements.cipher.value.trim() === "";
});

function openPrimeList() {
  if (!elements.primeList.hasChildNodes()) {
    const primes = [];
    for (let value = 2; value <= 10000; value += 1) {
      if (isPrime(BigInt(value))) primes.push(value);
    }
    elements.primeList.innerHTML = primes.map((prime) => `<span>${prime.toLocaleString("ko-KR")}</span>`).join("");
  }
  elements.primeModal.hidden = false;
  document.body.classList.add("prime-modal-open");
  elements.closePrimeModal.focus();
}

function closePrimeList() {
  elements.primeModal.hidden = true;
  document.body.classList.remove("prime-modal-open");
  elements.showPrimes.focus();
}

function generateKeys() {
  clearMessage(elements.keyMessage);
  try {
    const p = readSmallInteger(elements.p, "p");
    const q = readSmallInteger(elements.q, "q");
    if (p < 3n || q < 3n) throw new Error("3 이상의 소수를 입력하세요.");
    if (p > 10000n || q > 10000n) throw new Error("실습에서는 10,000 이하의 소수를 사용하세요.");
    currentKey = createKeyPair(p, q);
    currentCipher = null;
    elements.message.max = (currentKey.n - 1n).toString();
    elements.processExplanation.hidden = true;

    elements.n.textContent = format(currentKey.n);
    elements.phi.textContent = format(currentKey.phi);
    elements.publicKey.textContent = `(${format(currentKey.n)}, ${format(currentKey.e)})`;
    elements.privateKey.textContent = format(currentKey.d);
    elements.keyCalculation.innerHTML = [
      `n = ${p} × ${q} = <strong>${currentKey.n}</strong>`,
      `키 계산값 = (${p} − 1) × (${q} − 1) = <strong>${currentKey.phi}</strong>`,
      `${currentKey.e} × ${currentKey.d} mod ${currentKey.phi} = <strong>1</strong>`
    ].join("<br>");
    elements.keyResults.hidden = false;
    elements.keyCalculation.hidden = false;
    setMessage(elements.keyMessage, "키 생성이 완료되었습니다.", true);

    elements.encrypt.disabled = false;
    elements.decrypt.disabled = true;
    elements.encryptResult.hidden = true;
    elements.decryptResult.hidden = true;
    elements.cipher.value = "";
    elements.attackN.textContent = format(currentKey.n);
    elements.attackE.textContent = format(currentKey.e);
    elements.attackC.textContent = "암호화 필요";
    elements.attack.disabled = true;
    elements.attackOutput.hidden = true;
    setActiveStep(2);
  } catch (error) {
    currentKey = null;
    elements.keyResults.hidden = true;
    elements.keyCalculation.hidden = true;
    elements.encrypt.disabled = true;
    setMessage(elements.keyMessage, error.message);
  }
}

function encryptMessage() {
  clearMessage(elements.encryptMessage);
  try {
    if (!currentKey) throw new Error("먼저 키를 생성하세요.");
    const message = readInteger(elements.message, "메시지");
    currentCipher = encryptNumber(message, currentKey);
    elements.processExplanation.hidden = true;
    elements.cipherValue.textContent = format(currentCipher);
    elements.encryptFormula.textContent = `C = ${message}^${currentKey.e} mod ${currentKey.n} = ${currentCipher}`;
    elements.encryptResult.hidden = false;
    elements.cipher.value = currentCipher.toString();
    elements.decrypt.disabled = false;
    elements.attackC.textContent = format(currentCipher);
    elements.attack.disabled = false;
    elements.attackOutput.hidden = true;
    setMessage(elements.encryptMessage, `메시지 ${message}를 암호문 ${currentCipher}(으)로 바꿨습니다.`, true);
    setActiveStep(3);
  } catch (error) {
    elements.encryptResult.hidden = true;
    setMessage(elements.encryptMessage, error.message);
  }
}

function decryptMessage() {
  clearMessage(elements.decryptMessage);
  try {
    if (!currentKey) throw new Error("먼저 키를 생성하세요.");
    const cipher = readInteger(elements.cipher, "암호문");
    const plain = decryptNumber(cipher, currentKey);
    elements.plainValue.textContent = format(plain);
    elements.decryptFormula.textContent = `M = ${cipher}^${currentKey.d} mod ${currentKey.n} = ${plain}`;
    elements.decryptResult.hidden = false;
    elements.processSummary.textContent = `원문 ${plain}을 공개키 (${currentKey.n}, ${currentKey.e})로 암호화해 암호문 ${cipher}(으)로 바꾸고, 개인키 ${currentKey.d}로 복호화하여 다시 원문 ${plain}을 되찾았습니다.`;
    elements.processExplanation.hidden = false;
    elements.processExplanation.scrollIntoView({ behavior: "smooth", block: "nearest" });
    setMessage(elements.decryptMessage, `암호문에서 메시지 ${plain}을(를) 되찾았습니다.`, true);
    setActiveStep(3, true);
    showToast("암호화·복호화 실험에 성공했습니다.");
  } catch (error) {
    elements.decryptResult.hidden = true;
    setMessage(elements.decryptMessage, error.message);
  }
}

function runAttack() {
  clearMessage(elements.attackMessage);
  try {
    if (!currentKey || currentCipher === null) throw new Error("키를 만든 뒤 메시지를 암호화하세요.");
    const factor = factorByTrialDivision(currentKey.n);
    if (!isPrime(factor.p) || !isPrime(factor.q)) throw new Error("찾은 약수가 두 소수로 이루어지지 않았습니다.");
    const phi = (factor.p - 1n) * (factor.q - 1n);
    const crackedD = modInverse(currentKey.e, phi);
    const recovered = modPow(currentCipher, crackedD, currentKey.n);

    elements.factorResult.textContent = `${factor.p} × ${factor.q}`;
    elements.attemptResult.textContent = `${factor.attempts.toLocaleString("ko-KR")}회`;
    elements.crackedKeyResult.textContent = crackedD.toString();
    elements.recoveredResult.textContent = recovered.toString();
    elements.attackOutput.hidden = false;
    setMessage(elements.attackMessage, "작은 n을 소인수분해해 개인키와 메시지를 복원했습니다.", true);
  } catch (error) {
    elements.attackOutput.hidden = true;
    setMessage(elements.attackMessage, error.message);
  }
}

function runExperiment() {
  const pairs = [[3n, 11n], [11n, 17n], [29n, 31n], [97n, 101n], [211n, 223n]];
  const rows = pairs.map(([p, q]) => {
    const n = p * q;
    const result = factorByTrialDivision(n);
    return { p, q, n, attempts: result.attempts };
  });
  const max = Math.max(...rows.map((row) => row.attempts));
  elements.experimentBody.innerHTML = rows.map((row) => `
    <tr>
      <td>${format(row.p)}</td>
      <td>${format(row.q)}</td>
      <td>${format(row.n)}</td>
      <td>${row.attempts.toLocaleString("ko-KR")}회</td>
      <td><div class="bar-track" aria-label="최대값 대비 ${Math.round(row.attempts / max * 100)}퍼센트"><div class="bar-fill" style="width:${Math.max(5, row.attempts / max * 100)}%"></div></div></td>
    </tr>`).join("");
  elements.experimentWrap.hidden = false;
  elements.experiment.textContent = "비교 실험 다시 실행";
  showToast("5가지 공개키의 소인수분해 시도 횟수를 비교했습니다.");
}

function readSmallInteger(input, name) {
  const value = readInteger(input, name);
  return value;
}

function readInteger(input, name) {
  const raw = input.value.trim();
  if (!/^-?\d+$/.test(raw)) throw new Error(`${name}에 정수를 입력하세요.`);
  return BigInt(raw);
}

function format(value) {
  return value.toLocaleString("ko-KR");
}

function setMessage(target, message, ok = false) {
  target.textContent = message;
  target.classList.toggle("ok", ok);
}

function clearMessage(target) {
  setMessage(target, "", false);
}

function setActiveStep(step, complete = false) {
  [elements.step1, elements.step2, elements.step3].forEach((el, index) => {
    el.classList.toggle("is-active", index + 1 <= step || complete);
  });
}

let toastTimer;
function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("show"), 2800);
}

generateKeys();
