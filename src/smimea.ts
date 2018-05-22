/*!
 * smimea.js - SMIMEA for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/smimea.go
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6698
 */

'use strict';

import * as assert from "assert";
import * as crypto from "./crypto";
import * as dane from "./dane";
import {DaneMatchingType, DaneSelector, DaneUsage} from "./dane";
import * as util from "./util";
import {QuestionClass, Record, RecordData, RecordType, SMIMEARecord} from "./wire";

/*
 * SMIMEA
 */

export function create(cert: Buffer, name: string, email: string, options: any = {}): Record<RecordData> {
	// assert(Buffer.isBuffer(cert));
	assert(options && typeof options === 'object');

	let {ttl, usage, selector, matchingType} = options;

	if (ttl == null)
		ttl = 3600;

	if (usage == null)
		usage = DaneUsage.DIC;

	if (selector == null)
		selector = DaneSelector.SPKI;

	if (matchingType == null)
		matchingType = DaneMatchingType.SHA256;

	assert((ttl >>> 0) === ttl);
	assert((usage & 0xff) === usage);
	assert((selector & 0xff) === selector);
	assert((matchingType & 0xff) === matchingType);

	const rr = new Record();
	const rd = new SMIMEARecord();

	rr.name = encodeName(name, email);
	rr.type = RecordType.SMIMEA;
	rr.class = QuestionClass.IN;
	rr.ttl = ttl;
	rr.data = rd;
	rd.usage = usage;
	rd.selector = selector;
	rd.matchingType = matchingType;

	const hash = dane.sign(cert, selector, matchingType);

	if (!hash)
		throw new Error('Unknown selector or matching type.');

	rd.certificate = hash;

	return rr;
};

export function verify(rr: Record<SMIMEARecord>, cert: Buffer, name?: string, email?: string) {
	// assert(rr instanceof Record);
	assert(rr.type === RecordType.SMIMEA);

	const rd = rr.data;

	if (email != null) {
		if (!verifyName(rr, name, email))
			return false;
	}

	return dane.verify(cert, rd.selector, rd.matchingType, rd.certificate);
};

export function verifyName(rr: Record<SMIMEARecord>, name: string, email: string) {
	// assert(rr instanceof Record);
	assert(rr.type === RecordType.SMIMEA);
	const encoded = encodeName(name, email);
	return util.equal(rr.name, encoded);
};

export function encodeName(name: string, email: string) {
	assert(util.isName(name));
	assert(name.indexOf('_') === -1);
	// assert(typeof email === 'string');
	assert(email.length <= 255);

	const raw = Buffer.from(email, 'ascii');
	const hash = crypto.sha256.digest(raw);
	const hex = hash.toString('hex', 0, 28);

	const encoded = util.fqdn(`_${hex}._smimecert.${name}`);

	assert(util.isName(encoded));

	return encoded;
}

export function decodeName(name: string) {
	assert(util.isName(name));

	const labels = util.split(name);

	assert(labels.length >= 3);

	const hex = util.label(name, labels, 0);
	const smime = util.label(name, labels, 1);

	assert(hex.length > 0);
	assert(smime.length > 0);

	assert(hex[0] === '_');
	assert(smime[0] === '_');

	if (smime.toLowerCase() !== '_smimecert')
		throw new Error('Invalid SMIMEA name.');

	if (hex.length !== 57)
		throw new Error('Invalid SMIMEA hash.');

	const hash = Buffer.from(hex.substring(1), 'hex');

	if (hash.length !== 28)
		throw new Error('Invalid SMIMEA hash.');

	return {
		name: util.fqdn(util.from(name, labels, 2)),
		hash: hash
	};
}
