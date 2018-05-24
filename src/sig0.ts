/*!
 * sig0.js - SIG(0) for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/sig0.go
 */

'use strict';

import * as assert from "assert";
import * as bio from "@as-com/bufio";
import {algHashes, EncAlg, HashAlg, QuestionClass, RecordType} from "./constants";
import * as dnssec from "./dnssec";
import {algToHash, hashToHash} from "./dnssec";
import {readNameBR} from "./encoding";
import * as util from "./util";
import {KEYRecord, Record, SIGRecord} from "./wire";

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DEFAULT_FUDGE = 300;

/*
 * SIG(0)
 */

export function sign(msg: Buffer, key: Record<KEYRecord>, priv: Buffer, fudge: number, signer?: Function) {
	if (fudge == null)
		fudge = DEFAULT_FUDGE;

	// assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);
	// assert(key instanceof Record);
	assert(key.type === RecordType.KEY);
	// assert(Buffer.isBuffer(priv));
	assert((fudge >>> 0) === fudge);
	assert(signer == null || typeof signer === 'function');

	const now = util.now();
	const rr = new Record();
	const rd = new SIGRecord();

	rr.name = '.';
	rr.type = RecordType.SIG;
	rr.class = QuestionClass.ANY;
	rr.ttl = 0;
	rr.data = rd;
	rd.typeCovered = 0;
	rd.algorithm = key.data.algorithm;
	rd.labels = 0;
	rd.origTTL = 0;
	rd.expiration = now + fudge;
	rd.inception = now - fudge;
	rd.keyTag = key.data.keyTag();
	rd.signerName = '.';
	rd.signature = DUMMY;

	const pre = removeSIG(msg);
	const data = sigData(pre, rd, 0);

	if (rd.algorithm === EncAlg.PRIVATEDNS) {
		if (!signer)
			throw new Error('Signer not available.');

		rd.signature = signer(priv, data);
	} else {
		rd.signature = dnssec.signData(priv, data, rd.algorithm);
	}

	const arcount = pre.readUInt16BE(10, true);
	const size = rr.getSize();
	const bw = bio.write(pre.length + size);

	bw.copy(pre, 0, 10);
	bw.writeU16BE(arcount + 1);
	bw.copy(pre, 12, pre.length);
	rr.write(bw);

	return bw.render();
}

export function verify(msg: Buffer, key: Record<KEYRecord>, verifier?: Function) {
	// assert(Buffer.isBuffer(msg));
	// assert(key instanceof Record);
	// assert(key.type === RecordType.KEY);
	// assert(verifier == null || typeof verifier === 'function');

	const [pos, rr] = findSIG(msg);

	if (pos === -1)
		return false;

	const rd = rr.data;

	if (rd.algorithm !== key.data.algorithm)
		return false;

	if (rd.labels !== 0)
		return false;

	if (rd.origTTL !== 0)
		return false;

	const now = util.now();

	if (now < rd.inception)
		return false;

	if (now > rd.expiration)
		return false;

	if (rd.algorithm !== EncAlg.PRIVATEDNS) {
		if (rd.keyTag !== key.data.keyTag())
			return false;
	}

	if (rd.signerName !== '.')
		return false;

	const pre = msg.slice(0, pos);
	const data = sigData(pre, rd, -1);

	if (rd.algorithm === EncAlg.PRIVATEDNS) {
		if (!verifier)
			throw new Error('Verifier not available.');

		return verifier(rr, key, data);
	}

	return dnssec.verifyData(rr, key, data, rd.algorithm);
}

/*
 * Helpers
 */

function findSIG(msg: Buffer): [number, Record<SIGRecord> | null] {
	// assert(Buffer.isBuffer(msg));

	try {
		return _findSIG(msg);
	} catch (e) {
		return [-1, null];
	}
}

function _findSIG(msg): [number, Record<SIGRecord> | null] {
	const br = bio.read(msg);

	br.readU16BE();
	br.readU16BE();

	const qdcount = br.readU16BE();
	const ancount = br.readU16BE();
	const nscount = br.readU16BE();
	const arcount = br.readU16BE();

	if (arcount === 0)
		return [-1, null];

	for (let i = 0; i < qdcount; i++) {
		if (br.left() === 0)
			return [-1, null];

		readNameBR(br);
		br.seek(4);
	}

	for (let i = 0; i < ancount; i++) {
		if (br.left() === 0)
			return [-1, null];

		readNameBR(br);
		br.seek(8);
		br.seek(br.readU16BE());
	}

	for (let i = 0; i < nscount; i++) {
		if (br.left() === 0)
			return [-1, null];

		readNameBR(br);
		br.seek(8);
		br.seek(br.readU16BE());
	}

	for (let i = 0; i < arcount - 1; i++) {
		if (br.left() === 0)
			return [-1, null];

		readNameBR(br);
		br.seek(8);
		br.seek(br.readU16BE());
	}

	const offset = br.offset;
	const rr = Record.read<Record>(br);
	const rd = rr.data;

	if (rr.name !== '.')
		return [-1, null];

	if (rr.type !== RecordType.SIG)
		return [-1, null];

	if (rr.class !== QuestionClass.ANY)
		return [-1, null];

	if (rr.ttl !== 0)
		return [-1, null];

	if (rd.typeCovered !== 0)
		return [-1, null];

	return [offset, rr as Record<SIGRecord>];
}

function removeSIG(msg) {
	assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);

	const [pos] = findSIG(msg);

	if (pos === -1)
		return msg;

	const arcount = msg.readUInt16BE(10, true);
	const buf = Buffer.allocUnsafe(pos);
	msg.copy(buf, 0, 0, pos);
	buf.writeUInt16BE(arcount - 1, 10, true);

	return buf;
}

function sigData(msg, rd, offset) {
	assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);
	assert(rd instanceof SIGRecord);
	assert(Number.isSafeInteger(offset));

	const sig = rd.signature;
	const arcount = msg.readUInt16BE(10, true);

	if (arcount + offset < 0)
		throw new Error('Invalid offset.');

	rd.signature = DUMMY;

	let size = 0;
	size += rd.getSize();
	size += msg.length;

	const bw = bio.write(size);

	rd.write(bw);
	bw.copy(msg, 0, 10);
	bw.writeU16BE(arcount + offset);
	bw.copy(msg, 12, msg.length);

	rd.signature = sig;

	return bw.render();
}

/*
 * Expose
 */

export {EncAlg, HashAlg, algHashes, algToHash, hashToHash}
