/**
 * La primera parte del archivo es nuestro codigo customizado para SIB
 * La segunda parte es el codigo migrado de la libreria bouncycastle bcprov-jdk15-145.jar. Punto de inicio: clase org.bouncycastle.crypto.modes.CBCBlockCipher
 *
 */

/* Primera parte: codigo customizado para SIB */

/*
Ejemplo de prueba

generateMac(MOCKtext, MOCKmacClave)

Resultado
@##H2$@2-G77
*/

export var MOCKtext =
  "303137323032323035313058333138303941303030303030303030303033333435303020202020202020202020202020202030323030313034343138373720202020202020303732202020202020202020202020202020303238323834303030303035352020202020203231303030306f62202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202036323930303030303030413132332e2e";

export var MOCKmacClave = "1234567P";

var hexArray = [
  "0",
  "1",
  "2",
  "3",
  "4",
  "5",
  "6",
  "7",
  "8",
  "9",
  "a",
  "b",
  "c",
  "d",
  "e",
  "f",
];
var high = [];
for (var i = 0; i < 16; i++) {
  var b = i;
  high[i] = (b << 4) & 0xf0;
}

var low = [];
for (var i = 0; i < 16; i++) {
  b = i;
  low[i] = b & 0x0f;
}

function toByteArray(aString) {
  var bytes = [];
  for (var i = 0; i < aString.length; ++i) {
    bytes.push(aString.charCodeAt(i));
  }

  return bytes;
}

function hexStringToBytes(aString) {
  var b;
  var b2;
  var len = aString.length;
  var retval = [];

  var j = 0;
  for (var i = 0; i < len; i += 2) {
    b = high[getIndex(aString.charAt(i))];
    b2 = low[getIndex(aString.charAt(i + 1))];
    retval[j++] = b | b2;
  }

  return retval;
}

function getIndex(c) {
  if ("0" <= c && c <= "9") {
    return c.charCodeAt(0) - "0".charCodeAt(0);
  } else if ("a" <= c && c <= "f") {
    return c.charCodeAt(0) - "a".charCodeAt(0) + 10;
  } else if ("A" <= c && c <= "F") {
    return c.charCodeAt(0) - "A".charCodeAt(0) + 10;
  } else {
    return -1;
  }
}

function bytesToHexString(aByteArray) {
  var position;
  var returnBuffer = "";

  for (position = 0; position < aByteArray.length; position++) {
    returnBuffer += hexArray[(aByteArray[position] >> 4) & 0x0f];
    returnBuffer += hexArray[aByteArray[position] & 0x0f];
  }

  return returnBuffer;
}

function encryptInternal(plaintext, simetricKEY) {
  var mac = [];

  for (var i = 0; i < 8; i++) {
    simetricKEY[i] <<= 1;
  }

  init(simetricKEY); // funcion init(...) de libreria migrada bouncycastle
  var ciphertext = createByteArrayWithZeroes(plaintext.length);

  var outputLen;
  var aux = plaintext.length;
  var pt = 0;

  while (aux > 0) {
    outputLen = processBlock(plaintext, pt, ciphertext, pt); // funcion processBlock(...) de libreria migrada bouncycastle
    aux = aux - outputLen;
    pt = pt + outputLen;
  }

  for (var i = ciphertext.length - 8, j = 0; i < ciphertext.length; i++) {
    mac[j++] = ciphertext[i];
  }

  return extension(mac);
}

function extension(mac) {
  var salida = [];

  for (var i = 0, j = 0; i < 8; i += 2) {
    var a = mac[i];
    var b = mac[i + 1];

    if (a < 0) {
      a += 256;
    }
    if (b < 0) {
      b += 256;
    }
    var num = a * 256 + b;

    salida[j++] = truncateDecimals(convertToByte((num % 48) + 32));
    num /= 48;
    salida[j++] = truncateDecimals(convertToByte((num % 48) + 32));
    num /= 48;
    salida[j++] = truncateDecimals(convertToByte((num % 48) + 32));
  }

  return salida;
}

function truncateDecimals(aNumber) {
  var dotIndex = aNumber.toString().indexOf(".");
  if (dotIndex == -1) {
    return aNumber;
  } else {
    return parseInt(aNumber.toString().substring(0, dotIndex));
  }
}

/* Segunda parte: codigo migrado de la libreria bouncycastle */

var iv;
var cbcV;
var cbcNextV;
var workingKey;
var blockSize = 8;

var pc1 = [
  56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34,
  26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
];
var pc2 = [
  13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26,
  19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33,
  52, 45, 41, 49, 35, 28, 31,
];
var totrot = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];
var bytebit = [0o200, 0o100, 0o40, 0o20, 0o10, 0o4, 0o2, 0o1];
var bigbyte = [
  0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000,
  0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20,
  0x10, 0x8, 0x4, 0x2, 0x1,
];
var SP1 = [
  0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404,
  0x00000004, 0x00010000, 0x00000400, 0x01010400, 0x01010404, 0x00000400,
  0x01000404, 0x01010004, 0x01000000, 0x00000004, 0x00000404, 0x01000400,
  0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
  0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404,
  0x00010404, 0x01000000, 0x00010000, 0x01010404, 0x00000004, 0x01010000,
  0x01010400, 0x01000000, 0x01000000, 0x00000400, 0x01010004, 0x00010000,
  0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
  0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404,
  0x00010404, 0x01010400, 0x00000404, 0x01000400, 0x01000400, 0x00000000,
  0x00010004, 0x00010400, 0x00000000, 0x01010004,
];
var SP2 = [
  0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020,
  0x80100020, 0x80008020, 0x80000020, 0x80108020, 0x80108000, 0x80000000,
  0x80008000, 0x00100000, 0x00000020, 0x80100020, 0x00108000, 0x00100020,
  0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
  0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000,
  0x80100000, 0x00008020, 0x00000000, 0x00108020, 0x80100020, 0x00100000,
  0x80008020, 0x80100000, 0x80108000, 0x00008000, 0x80100000, 0x80008000,
  0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
  0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020,
  0x80000020, 0x00100020, 0x00108000, 0x00000000, 0x80008000, 0x00008020,
  0x80000000, 0x80100020, 0x80108020, 0x00108000,
];
var SP3 = [
  0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000,
  0x00020208, 0x08000200, 0x00020008, 0x08000008, 0x08000008, 0x00020000,
  0x08020208, 0x00020008, 0x08020000, 0x00000208, 0x08000000, 0x00000008,
  0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
  0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208,
  0x00000200, 0x08000000, 0x08020200, 0x08000000, 0x00020008, 0x00000208,
  0x00020000, 0x08020200, 0x08000200, 0x00000000, 0x00000200, 0x00020008,
  0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
  0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208,
  0x00020200, 0x08000008, 0x08020000, 0x08000208, 0x00000208, 0x08020000,
  0x00020208, 0x00000008, 0x08020008, 0x00020200,
];
var SP4 = [
  0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081,
  0x00800001, 0x00002001, 0x00000000, 0x00802000, 0x00802000, 0x00802081,
  0x00000081, 0x00000000, 0x00800080, 0x00800001, 0x00000001, 0x00002000,
  0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
  0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080,
  0x00802081, 0x00000081, 0x00800080, 0x00800001, 0x00802000, 0x00802081,
  0x00000081, 0x00000000, 0x00000000, 0x00802000, 0x00002080, 0x00800080,
  0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
  0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001,
  0x00802080, 0x00800081, 0x00002001, 0x00002080, 0x00800000, 0x00802001,
  0x00000080, 0x00800000, 0x00002000, 0x00802080,
];
var SP5 = [
  0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100,
  0x40000000, 0x02080000, 0x40080100, 0x00080000, 0x02000100, 0x40080100,
  0x42000100, 0x42080000, 0x00080100, 0x40000000, 0x02000000, 0x40080000,
  0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
  0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000,
  0x42000000, 0x00080100, 0x00080000, 0x42000100, 0x00000100, 0x02000000,
  0x40000000, 0x02080000, 0x42000100, 0x40080100, 0x02000100, 0x40000000,
  0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
  0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000,
  0x40080000, 0x42000000, 0x00080100, 0x02000100, 0x40000100, 0x00080000,
  0x00000000, 0x40080000, 0x02080100, 0x40000100,
];
var SP6 = [
  0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010,
  0x20404010, 0x00400000, 0x20004000, 0x00404010, 0x00400000, 0x20000010,
  0x00400010, 0x20004000, 0x20000000, 0x00004010, 0x00000000, 0x00400010,
  0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
  0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000,
  0x20404000, 0x20000000, 0x20004000, 0x00000010, 0x20400010, 0x00404000,
  0x20404010, 0x00400000, 0x00004010, 0x20000010, 0x00400000, 0x20004000,
  0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
  0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000,
  0x20400000, 0x00404010, 0x00004000, 0x00400010, 0x20004010, 0x00000000,
  0x20404000, 0x20000000, 0x00400010, 0x20004010,
];
var SP7 = [
  0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802,
  0x00200802, 0x04200800, 0x04200802, 0x00200000, 0x00000000, 0x04000002,
  0x00000002, 0x04000000, 0x04200002, 0x00000802, 0x04000800, 0x00200802,
  0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
  0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002,
  0x04000000, 0x00200800, 0x04000000, 0x00200800, 0x00200000, 0x04000802,
  0x04000802, 0x04200002, 0x04200002, 0x00000002, 0x00200002, 0x04000000,
  0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
  0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000,
  0x00000002, 0x04200802, 0x00000000, 0x00200802, 0x04200000, 0x00000800,
  0x04000002, 0x04000800, 0x00000800, 0x00200002,
];
var SP8 = [
  0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040,
  0x00000040, 0x10000000, 0x00040040, 0x10040000, 0x10041040, 0x00041000,
  0x10041000, 0x00041040, 0x00001000, 0x00000040, 0x10040000, 0x10000040,
  0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
  0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000,
  0x00041040, 0x00040000, 0x00041040, 0x00040000, 0x10041000, 0x00001000,
  0x00000040, 0x10040040, 0x00001000, 0x00041040, 0x10001000, 0x00000040,
  0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
  0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000,
  0x10001040, 0x00000000, 0x10041040, 0x00041000, 0x00041000, 0x00001040,
  0x00001040, 0x00040040, 0x10000000, 0x10041000,
];

function init(key) {
  iv = createByteArrayWithZeroes(8);
  cbcV = iv;
  cbcNextV = createByteArrayWithZeroes(blockSize);

  workingKey = generateWorkingKey(key);
}

function generateWorkingKey(key) {
  var newKey = [];
  var pc1m = [];
  var pcr = [];

  for (var j = 0; j < 56; j++) {
    var l = pc1[j];

    pc1m[j] = (key[l >>> 3] & bytebit[l & 0o7]) != 0;
  }

  for (var i = 0; i < 16; i++) {
    var l;
    var m;
    var n;

    m = i << 1;

    n = m + 1;
    newKey[m] = newKey[n] = 0;

    for (var j = 0; j < 28; j++) {
      l = j + totrot[i];
      if (l < 28) {
        pcr[j] = pc1m[l];
      } else {
        pcr[j] = pc1m[l - 28];
      }
    }

    for (var j = 28; j < 56; j++) {
      l = j + totrot[i];
      if (l < 56) {
        pcr[j] = pc1m[l];
      } else {
        pcr[j] = pc1m[l - 28];
      }
    }

    for (var j = 0; j < 24; j++) {
      if (pcr[pc2[j]]) {
        newKey[m] |= bigbyte[j];
      }

      if (pcr[pc2[j + 24]]) {
        newKey[n] |= bigbyte[j];
      }
    }
  }

  for (var i = 0; i != 32; i += 2) {
    var i1;
    var i2;

    i1 = newKey[i];
    i2 = newKey[i + 1];

    newKey[i] =
      ((i1 & 0x00fc0000) << 6) |
      ((i1 & 0x00000fc0) << 10) |
      ((i2 & 0x00fc0000) >>> 10) |
      ((i2 & 0x00000fc0) >>> 6);

    newKey[i + 1] =
      ((i1 & 0x0003f000) << 12) |
      ((i1 & 0x0000003f) << 16) |
      ((i2 & 0x0003f000) >>> 4) |
      (i2 & 0x0000003f);
  }

  return newKey;
}

function processBlock(inn, inOff, out, outOff) {
  for (var i = 0; i < blockSize; i++) {
    cbcV[i] ^= inn[inOff + i];
  }

  var length = internalProcessBlock(workingKey, cbcV, 0, out, outOff);

  arraycopy(out, outOff, cbcV, 0, cbcV.length);

  return length;
}

function arraycopy(src, srcPos, dest, destPos, length) {
  for (var i = 0; i < length; i++) {
    dest[destPos + i] = src[srcPos + i];
  }
}

function internalProcessBlock(wKey, inn, inOff, out, outOff) {
  var work;
  var right;
  var left;

  left = (inn[inOff + 0] & 0xff) << 24;
  left |= (inn[inOff + 1] & 0xff) << 16;
  left |= (inn[inOff + 2] & 0xff) << 8;
  left |= inn[inOff + 3] & 0xff;

  right = (inn[inOff + 4] & 0xff) << 24;
  right |= (inn[inOff + 5] & 0xff) << 16;
  right |= (inn[inOff + 6] & 0xff) << 8;
  right |= inn[inOff + 7] & 0xff;

  work = ((left >>> 4) ^ right) & 0x0f0f0f0f;
  right ^= work;
  left ^= work << 4;
  work = ((left >>> 16) ^ right) & 0x0000ffff;
  right ^= work;
  left ^= work << 16;
  work = ((right >>> 2) ^ left) & 0x33333333;
  left ^= work;
  right ^= work << 2;
  work = ((right >>> 8) ^ left) & 0x00ff00ff;
  left ^= work;
  right ^= work << 8;
  right = ((right << 1) | ((right >>> 31) & 1)) & 0xffffffff;
  work = (left ^ right) & 0xaaaaaaaa;
  left ^= work;
  right ^= work;
  left = ((left << 1) | ((left >>> 31) & 1)) & 0xffffffff;

  for (var round = 0; round < 8; round++) {
    var fval;

    work = (right << 28) | (right >>> 4);
    work ^= wKey[round * 4 + 0];
    fval = SP7[work & 0x3f];
    fval |= SP5[(work >>> 8) & 0x3f];
    fval |= SP3[(work >>> 16) & 0x3f];
    fval |= SP1[(work >>> 24) & 0x3f];
    work = right ^ wKey[round * 4 + 1];
    fval |= SP8[work & 0x3f];
    fval |= SP6[(work >>> 8) & 0x3f];
    fval |= SP4[(work >>> 16) & 0x3f];
    fval |= SP2[(work >>> 24) & 0x3f];
    left ^= fval;
    work = (left << 28) | (left >>> 4);
    work ^= wKey[round * 4 + 2];
    fval = SP7[work & 0x3f];
    fval |= SP5[(work >>> 8) & 0x3f];
    fval |= SP3[(work >>> 16) & 0x3f];
    fval |= SP1[(work >>> 24) & 0x3f];
    work = left ^ wKey[round * 4 + 3];
    fval |= SP8[work & 0x3f];
    fval |= SP6[(work >>> 8) & 0x3f];
    fval |= SP4[(work >>> 16) & 0x3f];
    fval |= SP2[(work >>> 24) & 0x3f];
    right ^= fval;
  }

  right = (right << 31) | (right >>> 1);
  work = (left ^ right) & 0xaaaaaaaa;
  left ^= work;
  right ^= work;
  left = (left << 31) | (left >>> 1);
  work = ((left >>> 8) ^ right) & 0x00ff00ff;
  right ^= work;
  left ^= work << 8;
  work = ((left >>> 2) ^ right) & 0x33333333;
  right ^= work;
  left ^= work << 2;
  work = ((right >>> 16) ^ left) & 0x0000ffff;
  left ^= work;
  right ^= work << 16;
  work = ((right >>> 4) ^ left) & 0x0f0f0f0f;
  left ^= work;
  right ^= work << 4;

  out[outOff + 0] = convertToByte((right >>> 24) & 0xff);
  out[outOff + 1] = convertToByte((right >>> 16) & 0xff);
  out[outOff + 2] = convertToByte((right >>> 8) & 0xff);
  out[outOff + 3] = convertToByte(right & 0xff);
  out[outOff + 4] = convertToByte((left >>> 24) & 0xff);
  out[outOff + 5] = convertToByte((left >>> 16) & 0xff);
  out[outOff + 6] = convertToByte((left >>> 8) & 0xff);
  out[outOff + 7] = convertToByte(left & 0xff);

  return blockSize;
}

function convertToByte(aNumber) {
  if (aNumber > 127) {
    return aNumber - 256;
  } else {
    return aNumber;
  }
}

function createByteArrayWithZeroes(length) {
  var byteArray = [];
  for (var i = 0; i < length; ++i) {
    byteArray.push(0);
  }

  return byteArray;
}

function hex_to_ascii(str1) {
  var hex = str1.toString();
  var str = "";
  for (var n = 0; n < hex.length; n += 2) {
    str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
  }
  return str;
}

export function generateMac(text, macClave) {
  var textBytes = hexStringToBytes(text);
  var macClaveBytes = toByteArray(macClave);
  var mac = encryptInternal(textBytes, macClaveBytes);
  var macReturned = bytesToHexString(mac);
  // Apparently, this conversion is not necessary
  var asciiMac = hex_to_ascii(macReturned);
  console.log({
    textBytes,
    macClaveBytes,
    mac,
    macReturned,
    asciiMac,
  });

  return macReturned;
}
