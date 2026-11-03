// Мини-QR-генератор: byte mode, ECC L, версии 1–9, авто-маска со штрафами.
// Без зависимостей. Экспортирует qrMatrix(text) -> {size, get(x,y), mask, version}
'use strict';
const QR = (() => {
  // GF(256) с примитивным полиномом 0x11D
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  for (let i = 0, x = 1; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x <<= 1; if (x & 0x100) x ^= 0x11D;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const mul = (a, b) => (a && b) ? EXP[LOG[a] + LOG[b]] : 0;

  // [eccLen, blockCount, dataCodewordsPerBlock] для ECC L, версии 1..9
  const VER = [null,
    [7, 1, 19], [10, 1, 34], [15, 1, 55], [20, 1, 80], [26, 1, 108],
    [18, 2, 68], [20, 2, 78], [24, 2, 97], [30, 2, 116]];
  const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46]];

  function rsGen(deg) {
    let poly = [1];
    for (let i = 0; i < deg; i++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= mul(poly[j], EXP[i]);
      }
      poly = next;
    }
    return poly;
  }
  function rsECC(data, deg) {
    const gen = rsGen(deg);
    const rem = new Array(deg).fill(0);
    for (let i = 0; i < data.length; i++) {
      const factor = data[i] ^ rem[0];
      rem.shift(); rem.push(0);
      if (factor) for (let j = 0; j < deg; j++) rem[j] ^= mul(gen[j + 1], factor);
    }
    return rem;
  }

  function fmtBits(mask) { // ECC L = 01, BCH(15,5), маскирование 0x5412
    const d = (1 << 3) | mask;
    let rem = d;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    return ((d << 10) | rem) ^ 0x5412;
  }
  function verBits(ver) { // BCH(18,6), только для версий 7+
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    return (ver << 12) | rem;
  }
  const MASK_FN = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x, y) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
    (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
    (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
    (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
  ];

  function buildMatrix(ver, codewords, mask) {
    const size = 17 + 4 * ver;
    const m = Array.from({ length: size }, () => new Array(size).fill(false));
    const fn = Array.from({ length: size }, () => new Array(size).fill(false));
    const set = (x, y, v) => { m[y][x] = v; fn[y][x] = true; };

    function finder(cx, cy) {
      for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, d !== 2 && d !== 4);
      }
    }
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);

    for (let i = 8; i < size - 8; i++) { // тайминг
      if (!fn[6][i]) set(i, 6, i % 2 === 0);
      if (!fn[i][6]) set(6, i, i % 2 === 0);
    }
    const al = ALIGN[ver]; // паттерны выравнивания: пропускаем только 3 угла с finder'ами
    const nA = al.length;
    for (let j = 0; j < nA; j++) for (let i = 0; i < nA; i++) {
      if ((i === 0 && j === 0) || (i === 0 && j === nA - 1) || (i === nA - 1 && j === 0)) continue;
      const ax = al[i], ay = al[j];
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
        set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
    if (ver >= 7) { // информация о версии: два блока 3x6
      const vb = verBits(ver);
      for (let i = 0; i < 18; i++) {
        const b = ((vb >>> i) & 1) !== 0;
        const a = size - 11 + (i % 3), c = Math.floor(i / 3);
        set(a, c, b); set(c, a, b);
      }
    }
    // формат-информация (резерв + запись)
    const fmt = fmtBits(mask);
    const bit = (d, i) => ((d >>> i) & 1) !== 0;
    for (let i = 0; i <= 5; i++) set(8, i, bit(fmt, i));
    set(8, 7, bit(fmt, 6)); set(8, 8, bit(fmt, 7)); set(7, 8, bit(fmt, 8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(fmt, i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(fmt, i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(fmt, i));
    set(8, size - 8, true); // тёмный модуль

    // данные зигзагом
    let i = 0;
    const totalBits = codewords.length * 8;
    const dataBit = k => ((codewords[k >>> 3] >>> (7 - (k & 7))) & 1) !== 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (fn[y][x]) continue;
          let b = i < totalBits ? dataBit(i) : false;
          if (MASK_FN[mask](x, y)) b = !b;
          m[y][x] = b;
          i++;
        }
      }
    }
    return m;
  }

  function penalty(m) {
    const size = m.length;
    let p = 0;
    // правило 1: серии по строкам и столбцам
    for (let y = 0; y < size; y++) {
      let run = 1;
      for (let x = 1; x < size; x++) {
        if (m[y][x] === m[y][x - 1]) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
        else run = 1;
      }
    }
    for (let x = 0; x < size; x++) {
      let run = 1;
      for (let y = 1; y < size; y++) {
        if (m[y][x] === m[y - 1][x]) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
        else run = 1;
      }
    }
    // правило 2: блоки 2x2
    for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++)
      if (m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) p += 3;
    // правило 3: паттерн 1011101 с 4 светлыми модулями по одной из сторон
    const pat = [true, false, true, true, true, false, true];
    const scanLine = line => {
      for (let i = 0; i + 11 <= line.length; i++) {
        let ok = true;
        for (let k = 0; k < 7; k++) if (line[i + 4 + (k < 4 ? 0 : 0)] === undefined) { ok = false; break; }
        if (!ok) continue;
        let match = true;
        for (let k = 0; k < 7; k++) if (line[i + 4 + k] !== pat[k]) { match = false; break; }
        if (match) {
          let clear = true;
          for (let k = 0; k < 4; k++) if (line[i + k]) { clear = false; break; }
          if (clear) p += 40;
        }
      }
      for (let i = 0; i + 11 <= line.length; i++) {
        let match = true;
        for (let k = 0; k < 7; k++) if (line[i + k] !== pat[k]) { match = false; break; }
        if (match) {
          let clear = true;
          for (let k = 7; k < 11; k++) if (line[i + k]) { clear = false; break; }
          if (clear) p += 40;
        }
      }
    };
    for (let y = 0; y < size; y++) scanLine(m[y]);
    for (let x = 0; x < size; x++) scanLine(m.map(r => r[x]));
    // правило 4: баланс тёмных модулей
    let dark = 0;
    for (const row of m) for (const b of row) if (b) dark++;
    const ratio = dark * 100 / (size * size);
    p += Math.floor(Math.abs(ratio - 50) / 5) * 10;
    return p;
  }

  function encode(text, forcedMask) {
    const bytes = new TextEncoder().encode(text);
    let ver = 0;
    for (let v = 1; v <= 9; v++) {
      const cap = VER[v][1] * VER[v][2];
      if (bytes.length <= cap - 2) { ver = v; break; }
    }
    if (!ver) throw new Error('QR_TOO_LONG');
    const [eccLen, blocks, dcw] = VER[ver];
    const cap = blocks * dcw;

    // битовый поток: mode(0100) + длина(8) + данные + терминатор + паддинг
    const bits = [];
    const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
    push(0b0100, 4); push(bytes.length, 8);
    for (const b of bytes) push(b, 8);
    const capBits = cap * 8;
    push(0, Math.min(4, capBits - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8)
      data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
    for (let pad = [0xEC, 0x11], k = 0; data.length < cap; k++) data.push(pad[k % 2]);

    // разбиение на блоки, ECC, интерлив
    const dBlocks = [], eBlocks = [];
    for (let b = 0; b < blocks; b++) {
      const slice = data.slice(b * dcw, (b + 1) * dcw);
      dBlocks.push(slice);
      eBlocks.push(rsECC(slice, eccLen));
    }
    const cw = [];
    for (let i = 0; i < dcw; i++) for (let b = 0; b < blocks; b++) cw.push(dBlocks[b][i]);
    for (let i = 0; i < eccLen; i++) for (let b = 0; b < blocks; b++) cw.push(eBlocks[b][i]);

    // выбор маски по минимальному штрафу (или принудительная — для тестов)
    let best = null, bestP = Infinity, bestMask = 0;
    const masks = forcedMask == null ? [0, 1, 2, 3, 4, 5, 6, 7] : [forcedMask];
    for (let mask = 0; mask < 8; mask++) {
      if (!masks.includes(mask)) continue;
      const m = buildMatrix(ver, cw, mask);
      const p = penalty(m);
      if (p < bestP) { bestP = p; best = m; bestMask = mask; }
    }
    return { size: best.length, version: ver, mask: bestMask, get: (x, y) => best[y][x], matrix: best };
  }

  return { encode, __cw: text => {
    const bytes = new TextEncoder().encode(text);
    let ver = 0;
    for (let v = 1; v <= 9; v++) { const cap = VER[v][1] * VER[v][2]; if (bytes.length <= cap - 2) { ver = v; break; } }
    const [eccLen, blocks, dcw] = VER[ver];
    const cap = blocks * dcw;
    const bits = [];
    const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
    push(0b0100, 4); push(bytes.length, 8);
    for (const b of bytes) push(b, 8);
    push(0, Math.min(4, cap * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
    for (let pad = [0xEC, 0x11], k = 0; data.length < cap; k++) data.push(pad[k % 2]);
    const dBlocks = [], eBlocks = [];
    for (let b = 0; b < blocks; b++) {
      const slice = data.slice(b * dcw, (b + 1) * dcw);
      dBlocks.push(slice); eBlocks.push(rsECC(slice, eccLen));
    }
    const cw = [];
    for (let i = 0; i < dcw; i++) for (let b = 0; b < blocks; b++) cw.push(dBlocks[b][i]);
    for (let i = 0; i < eccLen; i++) for (let b = 0; b < blocks; b++) cw.push(eBlocks[b][i]);
    return { ver, data, cw, ecc0: eBlocks[0] };
  } };
})();
if (typeof module !== 'undefined') module.exports = QR;

