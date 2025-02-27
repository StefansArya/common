// Copyright 2017-2022 @polkadot/util authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { objectKeys } from './keys';

/**
 * @name objectSpread
 * @summary Concats all sources into the destination
 */
export function objectSpread <T extends object> (dest: object, ...sources: (object | undefined | null)[]): T {
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];

    if (src) {
      const keys = objectKeys(src);

      for (let j = 0; j < keys.length; j++) {
        const key = keys[j];

        dest[key] = src[key];
      }
    }
  }

  return dest as T;
}
