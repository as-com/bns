/*!
 * tsig.js - TSIG for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/tsig.go
 */

'use strict';

import assert from "assert";
import bio from "bufio";
import {classes, tsigAlgs, types} from "./constants";
import * as crypto from "./crypto";
import {readNameBR, writeNameBW} from "./encoding";
import * as util from "./util";
import {Record, TSIGRecord} from "./wire";

/*
 * Constants
 */

const DEFAULT_FUDGE = 300;

/*
 * TSIG
 */

const tsig = exports;

tsig.sign = function sign(msg, sig, secret, requestMAC, timersOnly) {
	if (typeof sig === 'string') {
		const alg = sig;
		sig = new Record();
		sig.type = types.TSIG;
		sig.data = new TSIGRecord();
		sig.data.algorithm = alg;
	}

	if (requestMAC == null)
		requestMAC = null;

	if (timersOnly == null)
		timersOnly = false;

	assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);
	assert(sig instanceof Record);
	assert(sig.type === types.TSIG);
	assert(Buffer.isBuffer(secret));
	assert(requestMAC === null || Buffer.isBuffer(requestMAC));
	assert(typeof timersOnly === 'boolean');

	const id = msg.readUInt16BE(0, true);
	const rr = new Record();
	const rd = sig.data.clone();

	rr.name = '.';
	rr.type = types.TSIG;
	rr.class = classes.ANY;
	rr.ttl = 0;
	rr.data = rd;

	if (rd.algorithm === '.')
		rd.algorithm = tsigAlgs.SHA256;

	if (rd.timeSigned === 0)
		rd.timeSigned = util.now();

	if (rd.fudge === 0)
		rd.fudge = DEFAULT_FUDGE;

	rd.origID = id;

	const pre = removeTSIG(msg);
	const data = tsigData(pre, rd, requestMAC, timersOnly, 0);
	const hash = tsigHash(rd.algorithm, data, secret);

	if (!hash)
		throw new Error(`Unknown TSIG algorithm: ${rd.algorithm}.`);

	const arcount = pre.readUInt16BE(10, true);
	const size = rr.getSize();
	const bw = bio.write(pre.length + size);

	bw.copy(pre, 0, 10);
	bw.writeU16BE(arcount + 1);
	bw.copy(pre, 12, pre.length);
	rr.write(bw);

	return bw.render();
};

tsig.verify = function verify(msg, secret, requestMAC, timersOnly) {
	if (requestMAC == null)
		requestMAC = null;

	if (timersOnly == null)
		timersOnly = false;

	assert(Buffer.isBuffer(msg));
	assert(Buffer.isBuffer(secret));
	assert(requestMAC === null || Buffer.isBuffer(requestMAC));
	assert(typeof timersOnly === 'boolean');

	const [pos, rr] = findTSIG(msg);

	// No TSIG found.
	if (pos === -1)
		return false;

	const rd = rr.data;
	const inception = rd.timeSigned - rd.fudge;
	const expiration = rd.timeSigned + rd.fudge;
	const now = util.now();

	if (now < inception)
		return false;

	if (now > expiration)
		return false;

	const pre = msg.slice(0, pos);
	const data = tsigData(pre, rd, requestMAC, timersOnly, -1);
	const hash = tsigHash(rd.algorithm, data, secret);

	// Unknown algorithm.
	if (!hash)
		return false;

	// Safe: the length is not secret.
	if (rd.mac.length !== hash.length)
		return false;

	// Constant time equals.
	return crypto.ccmp(rd.mac, hash);
};

/*
 * Helpers
 */

function findTSIG(msg) {
	assert(Buffer.isBuffer(msg));

	try {
		return _findTSIG(msg);
	} catch (e) {
		return [-1, null];
	}
}

function _findTSIG(msg) {
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
	const rr = Record.read(br);

	if (rr.name !== '.')
		return [-1, null];

	if (rr.type !== types.TSIG)
		return [-1, null];

	if (rr.class !== classes.ANY)
		return [-1, null];

	if (rr.ttl !== 0)
		return [-1, null];

	return [offset, rr];
}

function removeTSIG(msg) {
	assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);

	const [pos] = findTSIG(msg);

	if (pos === -1)
		return msg;

	const arcount = msg.readUInt16BE(10, true);
	const buf = Buffer.allocUnsafe(pos);
	msg.copy(buf, 0, 0, pos);
	buf.writeUInt16BE(arcount - 1, 10, true);

	return buf;
}

function tsigData(msg, sig, requestMAC, timersOnly, offset) {
	assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);
	assert(sig instanceof TSIGRecord);
	assert(requestMAC === null || Buffer.isBuffer(requestMAC));
	assert(typeof timersOnly === 'boolean');
	assert(Number.isSafeInteger(offset));

	const arcount = msg.readUInt16BE(10, true);

	if (arcount + offset < 0)
		throw new Error('Bad offset.');

	let size = 0;

	if (requestMAC) {
		size += 2;
		size += requestMAC.length;
	}

	size += msg.length;

	if (timersOnly) {
		// Time signed and fudge.
		size += 8;
	} else {
		// Header, minus rdlen.
		size += 9;

		// TSIG minus mac and origID.
		size += sig.getSize();
		size -= 2 + sig.mac.length + 2;
	}

	const bw = bio.write(size);

	if (requestMAC) {
		bw.writeU16BE(requestMAC.length);
		bw.writeBytes(requestMAC);
	}

	bw.writeU16BE(sig.origID);
	bw.copy(msg, 2, 10);
	bw.writeU16BE(arcount + offset);
	bw.copy(msg, 12, msg.length);

	if (timersOnly) {
		bw.writeU16BE((sig.timeSigned / 0x100000000) >>> 0);
		bw.writeU32BE(sig.timeSigned >>> 0);
		bw.writeU16BE(sig.fudge);
	} else {
		const alg = sig.algorithm.toLowerCase();

		bw.writeU8(0);
		bw.writeU16BE(types.TSIG);
		bw.writeU16BE(classes.ANY);
		bw.writeU32BE(0);

		// No rdlen.

		writeNameBW(bw, alg);
		bw.writeU16BE((sig.timeSigned / 0x100000000) >>> 0);
		bw.writeU32BE(sig.timeSigned >>> 0);
		bw.writeU16BE(sig.fudge);

		// No mac or origID.

		bw.writeU16BE(sig.error);
		bw.writeU16BE(sig.other.length);
		bw.writeBytes(sig.other);
	}

	return bw.render();
}

function tsigHash(alg, data, secret) {
	assert(typeof alg === 'string');
	assert(Buffer.isBuffer(data));
	assert(Buffer.isBuffer(secret));

	switch (alg.toLowerCase()) {
		case tsigAlgs.MD5:
			return crypto.md5.mac(data, secret);
		case tsigAlgs.SHA1:
			return crypto.sha1.mac(data, secret);
		case tsigAlgs.SHA256:
			return crypto.sha256.mac(data, secret);
		case tsigAlgs.SHA512:
			return crypto.sha512.mac(data, secret);
	}

	return null;
}

/*
 * Expose
 */

tsig.algs = tsigAlgs;
