/*!
 * hsig.js - HSIG for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import * as assert from "assert";
import {KEYRecord, QuestionClass, Record, RecordType} from "./wire";
import * as sig0 from "./sig0";

/*
 * Constants
 */

const FUDGE_WINDOW = 21600; // 6 hours

/*
 * HSIG
 */

export function createKey(pub: Buffer) {
	// assert(Buffer.isBuffer(pub));
	assert(pub.length === 33);

	const rr = new Record<KEYRecord>();
	const rd = new KEYRecord();

	rr.name = '.';
	rr.type = RecordType.KEY;
	rr.class = QuestionClass.ANY;
	rr.ttl = 0;
	rr.data = rd;
	rd.flags = 0;
	rd.protocol = 0;
	rd.algorithm = sig0.EncAlg.PRIVATEDNS;
	rd.publicKey = pub;

	return rr;
}

export function sign(msg: Buffer, priv: Buffer, blake2b, secp256k1) {
	assert(Buffer.isBuffer(msg));
	assert(Buffer.isBuffer(priv) && priv.length === 32);
	assert(blake2b && typeof blake2b.digest === 'function');
	assert(secp256k1 && typeof secp256k1.sign === 'function');

	const pub = secp256k1.publicKeyCreate(priv, true);
	const key = createKey(pub);
	const fudge = FUDGE_WINDOW;

	return sig0.sign(msg, key, priv, fudge, (priv, data) => {
		const msg = blake2b.digest(data);
		return secp256k1.sign(msg, priv);
	});
}

export function verify(msg: Buffer, pub: Buffer, blake2b, secp256k1) {
	assert(Buffer.isBuffer(msg));
	assert(Buffer.isBuffer(pub) && pub.length === 33);
	assert(blake2b && typeof blake2b.digest === 'function');
	assert(secp256k1 && typeof secp256k1.verify === 'function');

	const key = createKey(pub);

	return sig0.verify(msg, key, (sig, key, data) => {
		const msg = blake2b.digest(data);
		const sigbuf = sig.data.signature;
		const keybuf = key.data.publicKey;
		return secp256k1.verify(msg, sigbuf, keybuf);
	});
}
