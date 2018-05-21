/*!
 * crypto.js - crypto for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

/*
 * Hashes
 */

export const md5 = undefined;
export const sha1 = undefined;
export const sha256 = undefined;
export const sha384 = undefined;
export const sha512 = undefined;
export const ccmp = undefined;

/*
 * RSA
 */

export function signRSA(hash, data, key) {
  throw new Error('Cannot sign.');
}

export function verifyRSA(hash, data, sig, key) {
  throw new Error('Cannot verify.');
}

/*
 * ECDSA
 */

export function signECDSA(curve, hash, data, key) {
  throw new Error('Cannot sign.');
}

export function verifyECDSA(curve, hash, data, sig, key) {
  throw new Error('Cannot verify.');
}

/*
 * EDDSA
 */

export function signEDDSA(curve, hash, data, key) {
  throw new Error('Cannot sign.');
}

export function verifyEDDSA(curve, hash, data, sig, key) {
  throw new Error('Cannot verify.');
}
