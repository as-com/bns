/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

import * as assert from "./util/assert";
import * as constants from "../src/constants";
import * as encoding from "../src/encoding";

const {RecordType} = constants;

const array = [
	RecordType.NS,
	RecordType.SOA,
	RecordType.RRSIG,
	RecordType.NSEC,
	RecordType.DNSKEY
];

describe('Encoding', function() {
  it('should serialize type bitmap', () => {
    const bitmap = encoding.toBitmap(array);

    for (const type of array)
      assert(encoding.hasType(bitmap, type), constants.typeToString(type));

    const arr = encoding.fromBitmap(bitmap);
    assert.deepStrictEqual(array, arr);
  });
});
