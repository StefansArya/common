// Copyright 2017-2022 @polkadot/util authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { ToBnOptions } from '../types';

import { BigInt } from '@polkadot/x-bigint';

import { objectSpread } from '../object/spread';
import { u8aToBigInt } from '../u8a/toBigInt';
import { hexToU8a } from './toU8a';

/**
 * @name hexToBigInt
 * @summary Creates a BigInt instance object from a hex string.
 */
export function hexToBigInt (value?: string | null, options: ToBnOptions = {}): bigint {
  return !value || value === '0x'
    ? BigInt(0)
    : u8aToBigInt(
      hexToU8a(value),
      objectSpread({ isLe: false, isNegative: false }, options)
    );
}
