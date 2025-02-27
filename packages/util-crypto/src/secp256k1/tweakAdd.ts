// Copyright 2017-2022 @polkadot/util-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { _0n, assert, BN, bnToU8a, hasBigInt, isU8a, nToU8a, u8aToBigInt } from '@polkadot/util';
import { BigInt } from '@polkadot/x-bigint';

import { BN_BE_256_OPTS, BN_BE_OPTS } from '../bn';

// pre-defined curve param as lifted form elliptic
// https://github.com/indutny/elliptic/blob/e71b2d9359c5fe9437fbf46f1f05096de447de57/lib/elliptic/curves.js#L182
const N = 'ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141'.replace(/ /g, '');
const N_BI = BigInt(`0x${N}`);
const N_BN = new BN(N, 'hex');

function addBi (seckey: Uint8Array, tweak: Uint8Array): Uint8Array {
  let res = u8aToBigInt(tweak, BN_BE_OPTS);

  assert(res < N_BI, 'Tweak parameter is out of range');

  res += u8aToBigInt(seckey, BN_BE_OPTS);

  if (res >= N_BI) {
    res -= N_BI;
  }

  assert(res !== _0n, 'Invalid resulting private key');

  return nToU8a(res, BN_BE_256_OPTS);
}

function addBn (seckey: Uint8Array, tweak: Uint8Array): Uint8Array {
  const res = new BN(tweak);

  assert(res.cmp(N_BN) < 0, 'Tweak parameter is out of range');

  res.iadd(new BN(seckey));

  if (res.cmp(N_BN) >= 0) {
    res.isub(N_BN);
  }

  assert(!res.isZero(), 'Invalid resulting private key');

  return bnToU8a(res, BN_BE_256_OPTS);
}

export function secp256k1PrivateKeyTweakAdd (seckey: Uint8Array, tweak: Uint8Array, onlyBn?: boolean): Uint8Array {
  assert(isU8a(seckey) && seckey.length === 32, 'Expected seckey to be an Uint8Array with length 32');
  assert(isU8a(tweak) && tweak.length === 32, 'Expected tweak to be an Uint8Array with length 32');

  return !hasBigInt || onlyBn
    ? addBn(seckey, tweak)
    : addBi(seckey, tweak);
}
