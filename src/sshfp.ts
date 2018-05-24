/*!
 * sshfp.js - SSHFP for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import * as assert from "assert";
import {QuestionClass, RecordType, SSHAlg, SSHHash} from "./constants";
import * as crypto from "./crypto";
import * as util from "./util";
import {Record, SSHFPRecord} from "./wire";

/*
 * SSHFP
 */

export function hash(key: Buffer, digestType: number) {
	// assert(Buffer.isBuffer(key));
	assert((digestType & 0xff) === digestType);

	switch (digestType) {
		case SSHHash.SHA1:
			return crypto.sha1.digest(key);
		case SSHHash.SHA256:
			return crypto.sha256.digest(key);
	}

	return null;
}

export function validate(key: Buffer, digestType: number, fingerprint: Buffer) {
	assert(Buffer.isBuffer(fingerprint));

	const _hash = hash(key, digestType);

	if (!_hash)
		return false;

	return _hash.equals(fingerprint);
}

export function create(key: Buffer, name: string, alg: number, digest: number) {
	assert(Buffer.isBuffer(key));

	assert((alg & 0xff) === alg);
	assert((digest & 0xff) === digest);

	const rr = new Record<SSHFPRecord>();
	const rd = new SSHFPRecord();

	rr.name = util.fqdn(name);
	rr.type = RecordType.SSHFP;
	rr.class = QuestionClass.IN;
	rr.ttl = 0;
	rr.data = rd;
	rd.algorithm = alg;
	rd.digestType = digest;

	return sign(rr, key);
}

export function sign(rr: Record<SSHFPRecord>, key: Buffer) {
	// assert(rr instanceof Record);
	assert(rr.type === RecordType.SSHFP);

	const rd = rr.data;
	const _hash = hash(key, rd.digestType);

	if (!_hash)
		throw new Error('Unknown digest type.');

	rd.fingerprint = _hash;

	return rr;
}

export function verify(rr: Record<SSHFPRecord>, key: Buffer) {
	// assert(rr instanceof Record);
	assert(rr.type === RecordType.SSHFP);

	const rd = rr.data;

	return validate(key, rd.digestType, rd.fingerprint);
}

/*
 * Expose
 */
export {SSHAlg as EncAlg, SSHHash as HashAlg}
