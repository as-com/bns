/*!
 * nsec3.js - NSEC3 for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/nsecx.go
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

import * as assert from "assert";
import * as base32 from "bs32";
import {NsecHash, RecordType} from "./constants";
import * as crypto from "./crypto";
import {hasType, packName} from "./encoding";
import {NSEC3Record, Question, Record} from "./wire";
import * as util from "./util";

/*
 * Constants
 */

const MAX_ITERATIONS = 512;

/*
 * NSEC3
 */

export function hashName(name: string, ha: number, iter: number, salt: Buffer) {
	// assert(typeof name === 'string');
	assert((ha & 0xff) === ha);
	assert((iter & 0xffff) === iter);
	// assert(Buffer.isBuffer(salt));

	// DoS vector.
	if (iter > MAX_ITERATIONS)
		return null;

	const nameRaw = packName(name.toLowerCase());
	const saltRaw = salt;

	let hash = null;

	switch (ha) {
		case NsecHash.SHA1:
			hash = crypto.sha1;
			break;
	}

	if (!hash)
		return null;

	const ctx = hash.hash();
	ctx.init();
	ctx.update(nameRaw);
	ctx.update(saltRaw);

	let nameHash = ctx.final();

	for (let i = 0; i < iter; i++) {
		ctx.init();
		ctx.update(nameHash);
		ctx.update(saltRaw);
		nameHash = ctx.final();
	}

	return nameHash;
}

export function cover(rr: Record<NSEC3Record>, name: string) {
	// assert(rr instanceof Record);
	assert(rr.type === RecordType.NSEC3);

	const rd = rr.data;
	const nameHash = hashName(name, rd.hash, rd.iterations, rd.salt);

	if (!nameHash)
		return false;

	const owner = rr.name;
	const label = util.split(owner);

	if (label.length < 2)
		return false;

	const owner32 = owner.substring(0, label[1] - 1);
	const ownerZone = owner.substring(label[1]);
	const ownerHash = decodeHex(owner32);

	if (!ownerHash)
		return false;

	if (ownerHash.length !== nameHash.length)
		return false;

	if (!util.isSubdomain(ownerZone, name))
		return false;

	const nextHash = rd.nextDomain;

	if (nextHash.length !== nameHash.length)
		return false;

	if (ownerHash.equals(nextHash))
		return false;

	if (ownerHash.compare(nextHash) > 0) {
		if (nameHash.compare(ownerHash) > 0)
			return true;
		return nameHash.compare(nextHash) < 0;
	}

	if (nameHash.compare(ownerHash) < 0)
		return false;

	return nameHash.compare(nextHash) < 0;
}

export function match(rr: Record<NSEC3Record>, name: string) {
	// assert(rr instanceof Record);
	assert(rr.type === RecordType.NSEC3);

	const rd = rr.data;
	const nameHash = hashName(name, rd.hash, rd.iterations, rd.salt);

	if (!nameHash)
		return false;

	const owner = rr.name;
	const label = util.split(owner);

	if (label.length < 2)
		return false;

	const owner32 = owner.substring(0, label[1] - 1);
	const ownerZone = owner.substring(label[1]);
	const ownerHash = decodeHex(owner32);

	if (!ownerHash)
		return false;

	if (ownerHash.length !== nameHash.length)
		return false;

	if (!util.isSubdomain(ownerZone, name))
		return false;

	if (ownerHash.equals(nameHash))
		return true;

	return false;
}

export function findClosestEncloser(name: string, nsec): [string, string] {
	assert(typeof name === 'string');
	assert(Array.isArray(nsec));

	const label = util.split(name);

	let nc = name;

	for (let i = 0; i < label.length; i++) {
		const z = name.substring(label[i]);
		const bm = findMatching(z, nsec);

		if (!bm)
			continue;

		if (i !== 0)
			nc = name.substring(label[i - 1]);

		return [z, nc];
	}

	return ['', ''];
}

export function findMatching(name: string, nsec: Record<NSEC3Record>[]) {
	// assert(typeof name === 'string');
	assert(Array.isArray(nsec));

	for (const rr of nsec) {
		if (match(rr, name))
			return rr.data.typeBitmap;
	}

	return null; // NSEC missing coverage
}

export function findCoverer(name: string, nsec: Record<NSEC3Record>[]) {
	// assert(typeof name === 'string');
	assert(Array.isArray(nsec));

	for (const rr of nsec) {
		if (cover(rr, name)) {
			const rd = rr.data;
			return [rd.typeBitmap, (rd.flags & 1) === 1];
		}
	}

	return [null, false]; // NSEC missing coverage
}

export function verifyNameError(qs, nsec: Record<NSEC3Record>[]) {
	const [ce, nc] = findClosestEncloser(qs.name, nsec);

	if (ce === '')
		return false; // NSEC missing coverage

	const [cv] = findCoverer(nc, nsec);

	if (!cv)
		return false; // NSEC missing coverage

	return true;
}

export function verifyNoData(qs: Question, nsec: Record<NSEC3Record>[]) {
	// assert(qs instanceof Question);
	assert(Array.isArray(nsec));

	const bm = findMatching(qs.name, nsec);

	if (!bm) {
		if (qs.type !== RecordType.DS)
			return false; // NSEC missing coverage

		const [ce, nc] = findClosestEncloser(qs.name, nsec);

		if (ce === '')
			return false; // NSEC missing coverage

		const [b, optOut] = findCoverer(nc, nsec);

		if (!b)
			return false; // NSEC missing coverage

		if (!optOut)
			return false; // NSEC opt out

		return true;
	}

	if (hasType(bm, qs.type))
		return false; // NSEC type exists

	if (hasType(bm, RecordType.CNAME))
		return false; // NSEC type exists

	return true;
}

export function verifyDelegation(delegation: string, nsec: Record<NSEC3Record>[]) {
	const bm = findMatching(delegation, nsec);

	if (!bm) {
		const [ce, nc] = findClosestEncloser(delegation, nsec);

		if (ce === '')
			return false; // NSEC missing coverage

		const [b, optOut] = findCoverer(nc, nsec);

		if (!b)
			return false; // NSEC missing coverage

		if (!optOut)
			return false; // NSEC opt out

		return true;
	}

	if (!hasType(bm, RecordType.NS))
		return false; // NSEC NS missing

	if (hasType(bm, RecordType.DS))
		return false; // NSEC bad delegation

	if (hasType(bm, RecordType.SOA))
		return false; // NSEC bad delegation

	return true;
};

/*
 * Helpers
 */

function decodeHex(str) {
	try {
		return base32.decodeHex(str);
	} catch (e) {
		return null;
	}
}

/*
 * Expose
 */
export {NsecHash as HashAlg}

