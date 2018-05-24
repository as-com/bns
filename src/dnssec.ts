/*!
 * js - DNSSEC for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/go
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

import * as assert from "assert";
import * as bio from "@as-com/bufio";
import {algHashes, EncAlg, HashAlg, KeyFlag, RecordType} from "./constants";
import * as crypto from "./crypto";
import {Hash} from "crypto";
import {packName, readName} from "./encoding";
import * as util from "./util";
import {countLabels, extractSet, isRRSet, splitName} from "./util";
import {DNSKEYRecord, DSRecord, Message, Record, RRSIGRecord} from "./wire";

/*
 * Constants
 */

export const algToHash = {
	[EncAlg.RSAMD5]: crypto.md5, // Deprecated in RFC 6725
	[EncAlg.RSASHA1]: crypto.sha1,
	[EncAlg.RSASHA1NSEC3SHA1]: crypto.sha1,
	[EncAlg.RSASHA256]: crypto.sha256,
	[EncAlg.ECDSAP256SHA256]: crypto.sha256,
	[EncAlg.ECDSAP384SHA384]: crypto.sha384,
	[EncAlg.RSASHA512]: crypto.sha512,
	[EncAlg.ED25519]: crypto.sha256
};

export const hashToHash = {
	[HashAlg.SHA1]: crypto.sha1,
	[HashAlg.SHA256]: crypto.sha256,
	[HashAlg.GOST94]: null,
	[HashAlg.SHA384]: crypto.sha384,
	[HashAlg.SHA512]: crypto.sha512
};

let $HACK: Hash;

/*
 * DNSSEC
 */

export function createDS(dnskey: Record<DNSKEYRecord>, digestType: HashAlg) {
	// assert(dnskey instanceof Record);
	assert(dnskey.type === RecordType.DNSKEY);
	assert((digestType & 0xff) === digestType);

	const dk = dnskey.data; // DNSKEY
	const hash = hashToHash[digestType];

	if (!hash)
		return null;

	const raw = dk.encode();
	const keyTag = dk.keyTag(raw);
	const owner = packName(dnskey.name);

	const ctx = hash.hash();
	ctx.init();
	ctx.update(owner);
	ctx.update(raw);

	const rr = new Record<DSRecord>();
	rr.name = dnskey.name;
	rr.class = dnskey.class;
	rr.type = RecordType.DS;
	rr.ttl = dnskey.ttl;

	const ds = new DSRecord();
	ds.algorithm = dk.algorithm;
	ds.digestType = digestType;
	ds.keyTag = keyTag;
	ds.digest = ctx.final();

	rr.data = ds;

	return rr;
}

export function signMessage(msg, name, key, priv, lifespan) {
	assert(msg instanceof Message);

	for (const section of msg.sections()) {
		const sigs = signSection(section, name, key, priv, lifespan);
		for (const sig of sigs)
			section.push(sig);
	}

	return msg;
}

export function signSection(section, name, key, priv, lifespan) {
	assert(Array.isArray(section));

	const set = new Set();
	const sigs = [];

	for (const rr of section)
		set.add(rr.type);

	for (const type of set) {
		if (type === RecordType.OPT
			|| type === RecordType.RRSIG
			|| type === RecordType.SIG) {
			continue;
		}

		const rrset = extractSet(section, name, type);

		if (rrset.length === 0)
			continue;

		const sig = rrsign(key, priv, rrset, lifespan);
		sigs.push(sig);
	}

	return sigs;
}

export function signType(section, type, key, priv, lifespan) {
	assert(Array.isArray(section));
	assert((type & 0xffff) === type);

	const rrset = extractSet(section, '', type);

	if (rrset.length === 0)
		return section;

	const sig = rrsign(key, priv, rrset, lifespan);

	section.push(sig);

	return section;
}

export function rrsign(key, priv, rrset, lifespan) {
	if (lifespan == null)
		lifespan = 14 * 24 * 60 * 60;

	assert(key instanceof Record);
	assert(key.type === RecordType.DNSKEY);
	assert(Array.isArray(rrset));
	assert((lifespan >>> 0) === lifespan);

	const sig = new Record();
	const s = new RRSIGRecord();

	sig.name = key.name;
	sig.ttl = key.ttl;
	sig.class = key.class;
	sig.type = RecordType.RRSIG;
	sig.data = s;

	s.keyTag = key.data.keyTag();
	s.signerName = key.name;
	s.algorithm = key.data.algorithm;
	s.inception = util.now() - lifespan;
	s.expiration = util.now() + lifespan;

	return sign(sig, priv, rrset);
}

export function sign(sig, priv, rrset) {
	assert(sig instanceof Record);
	assert(sig.type === RecordType.RRSIG);
	assert(Buffer.isBuffer(priv));
	assert(Array.isArray(rrset));

	const s = sig.data; // RRSIG

	if (!isRRSet(rrset))
		throw new Error('Invalid RR set.');

	if (s.keyTag === 0 || s.signerName.length === 0 || s.algorithm === 0)
		throw new Error('Invalid signature record.');

	sig.type = RecordType.RRSIG;
	sig.name = rrset[0].name;
	sig.class = rrset[0].class;
	sig.data = s;

	if (s.origTTL === 0)
		s.origTTL = rrset[0].ttl;

	s.typeCovered = rrset[0].type;
	s.labels = countLabels(rrset[0].name);

	if (rrset[0].name[0] === '*')
		s.labels -= 1;

	const data = signatureHash(sig, rrset);

	if (!data)
		throw new Error('Bad number of labels.');

	s.signature = signData(priv, data, s.algorithm);

	return sig;
}

export function signData(priv, data, algorithm) {
	assert(Buffer.isBuffer(priv));
	assert(Buffer.isBuffer(data));
	assert((algorithm & 0xff) === algorithm);

	const keybuf = priv;
	const hash = algToHash[algorithm];

	if (!hash)
		throw new Error('Unknown hash algorithm.');

	switch (algorithm) {
		case EncAlg.DSA:
		case EncAlg.DSANSEC3SHA1:
			throw new Error('Unsupported public key algorithm.');
		case EncAlg.RSAMD5:
		case EncAlg.RSASHA1:
		case EncAlg.RSASHA1NSEC3SHA1:
		case EncAlg.RSASHA256:
		case EncAlg.RSASHA512:
			return crypto.signRSA(hash, data, keybuf);
		case EncAlg.ECDSAP256SHA256:
			return crypto.signECDSA('p256', hash, data, keybuf);
		case EncAlg.ECDSAP384SHA384:
			return crypto.signECDSA('p384', hash, data, keybuf);
		case EncAlg.ED25519:
			return crypto.signEDDSA('ed25519', hash, data, keybuf);
		case EncAlg.ED448:
			throw new Error('Unsupported public key algorithm.');
	}

	throw new Error('Unknown public key algorithm.');
}

export function verify(sig, key, rrset) {
	assert(sig instanceof Record);
	assert(sig.type === RecordType.RRSIG);
	assert(key instanceof Record);
	assert(key.type === RecordType.DNSKEY);
	assert(Array.isArray(rrset));

	const s = sig.data; // RRSIG
	const k = key.data; // DNSKEY

	if (!isRRSet(rrset))
		return false; // Invalid RR set

	if (s.keyTag !== k.keyTag())
		return false; // Key tag mismatch

	if (sig.class !== key.class)
		return false; // Class mismatch

	if (s.algorithm !== k.algorithm)
		return false; // Algorithm mismatch

	if (s.signerName.toLowerCase() !== key.name.toLowerCase())
		return false; // Name mismatch

	if (k.protocol !== 3)
		return false; // Invalid protocol

	if (rrset[0].class !== sig.class)
		return false; // Class mismatch

	if (rrset[0].type !== s.typeCovered)
		return false; // Type mismatch

	const data = signatureHash(sig, rrset);

	if (!data)
		return false;

	return verifyData(sig, key, data, s.algorithm);
}

export function verifyData(sig, key, data, algorithm) {
	assert(sig instanceof Record);
	assert(sig.type === RecordType.RRSIG);
	assert(key instanceof Record);
	assert(key.type === RecordType.DNSKEY);
	assert(Buffer.isBuffer(data));
	assert((algorithm & 0xff) === algorithm);

	const keybuf = key.data.publicKey;
	const sigbuf = sig.data.signature;
	const hash = algToHash[algorithm];

	if (!hash)
		return false;

	switch (algorithm) {
		case EncAlg.DSA:
		case EncAlg.DSANSEC3SHA1:
			return false;
		case EncAlg.RSAMD5:
		case EncAlg.RSASHA1:
		case EncAlg.RSASHA1NSEC3SHA1:
		case EncAlg.RSASHA256:
		case EncAlg.RSASHA512:
			return crypto.verifyRSA(hash, data, sigbuf, keybuf);
		case EncAlg.ECDSAP256SHA256:
			return crypto.verifyECDSA('p256', hash, data, sigbuf, keybuf);
		case EncAlg.ECDSAP384SHA384:
			return crypto.verifyECDSA('p384', hash, data, sigbuf, keybuf);
		case EncAlg.ED25519:
			return crypto.verifyEDDSA('ed25519', hash, data, sigbuf, keybuf);
		case EncAlg.ED448:
			return false;
	}

	return false; // Unknown algorithm
}

export function signatureHash(sig, rrset) {
	assert(sig instanceof Record);
	assert(sig.type === RecordType.RRSIG);
	assert(Array.isArray(rrset));

	const s = sig.data; // RRSIG
	const records = [];

	for (const item of rrset) {
		assert(item instanceof Record);

		const rr = item.deepClone();
		const labels = splitName(rr.name);

		// Server is using wildcards.
		if (labels.length > s.labels) {
			const i = labels.length - s.labels;
			const name = labels.slice(i).join('.');
			rr.name = `*.${name}.`;
		}

		// Invalid RR set.
		if (labels.length < s.labels)
			return null;

		// Canonical TTL.
		rr.ttl = s.origTTL;

		// Canonicalize all domain
		// names (see RFC 4034).
		rr.canonical();

		// Push for sorting.
		records.push(rr.encode());
	}

	records.sort(compare);

	const tbs = s.toTBS();

	let size = 0;

	size += tbs.length;

	for (let i = 0; i < records.length; i++) {
		const raw = records[i];

		if (i > 0 && raw.equals(records[i - 1]))
			continue;

		size += raw.length;
	}

	const bw = bio.write(size);

	bw.writeBytes(tbs);

	for (let i = 0; i < records.length; i++) {
		const raw = records[i];

		if (i > 0 && raw.equals(records[i - 1]))
			continue;

		bw.writeBytes(raw);
	}

	return bw.render();
}

export function verifyDS(msg: Message, ds: Record<DSRecord>[], name: string) {
	// assert(msg instanceof Message);
	// assert(Array.isArray(ds));
	// assert(typeof name === 'string');

	if (ds.length === 0)
		return false;

	const kskMap = new Map();

	for (const rr of msg.answer) {
		if (rr.type !== RecordType.DNSKEY)
			continue;

		const rd = rr.data as DNSKEYRecord;

		if (rd.flags & KeyFlag.REVOKE)
			continue;

		if (!(rd.flags & KeyFlag.ZONE))
			continue;

		if (!util.equal(rr.name, name))
			continue;

		if (rd.flags & KeyFlag.SEP)
			kskMap.set(rd.keyTag(), rr);
	}

	const valid = new Map();

	for (const rr of ds) {
		// assert(rr instanceof Record);
		// assert(rr.type === RecordType.DS);

		const rd = rr.data;
		const dnskey = kskMap.get(rd.keyTag);

		if (!dnskey)
			continue;

		const ds = createDS(dnskey, rd.digestType);

		if (!ds)
			continue; // Failed to convert KSK (unknown alg).

		if (!ds.data.digest.equals(rd.digest))
			return null; // Mismatching DS.

		valid.set(rd.keyTag, dnskey);

		continue;
	}

	if (valid.size === 0)
		return null;

	return valid;
}

export function verifyZSK(msg, kskMap, name) {
	assert(msg instanceof Message);
	assert(kskMap instanceof Map);
	assert(typeof name === 'string');

	if (msg.answer.length === 0)
		return false; // No keys

	if (kskMap.size === 0)
		return false; // No keys

	const keys = [];
	const sigs = [];

	for (const rr of msg.answer) {
		const rd = rr.data;

		if (rr.type === RecordType.DNSKEY) {
			if (!util.equal(rr.name, name))
				continue;
			keys.push(rr);
			continue;
		}

		if (rr.type === RecordType.RRSIG) {
			if (rd.typeCovered !== RecordType.DNSKEY)
				continue;

			if (!util.equal(rr.name, name))
				continue;

			if (!kskMap.has(rd.keyTag))
				continue;

			sigs.push(rr);
			continue;
		}
	}

	if (keys.length === 0)
		return false; // No keys

	if (sigs.length === 0)
		return false; // No sigs

	for (const sig of sigs) {
		const s = sig.data;
		const dnskey = kskMap.get(s.keyTag);

		if (!dnskey)
			return false; // Missing DNS Key

		if (!s.validityPeriod())
			return false; // Invalid Signature Period

		if (!verify(sig, dnskey, keys))
			return false; // Invalid Signature
	}

	return true;
}

export function verifyRRSIG(msg, zskMap) {
	assert(msg instanceof Message);
	assert(zskMap instanceof Map);

	const isAnswer = msg.isAnswer();
	const isReferral = msg.isReferral();

	if (!isAnswer && !isReferral)
		return true;

	const set = new Set();

	let section = msg.answer;

	if (isReferral) {
		section = msg.authority;

		// We need a signed DS, NSEC3,
		// or NS record for a referral.
		if (util.hasType(section, RecordType.DS))
			set.add(RecordType.DS);

		if (util.hasType(section, RecordType.NSEC3))
			set.add(RecordType.NSEC3);
	}

	// If we don't have any specific
	// types to look for, verify
	// everything in the section.
	if (set.size === 0) {
		for (const rr of section) {
			// No signed signatures.
			if (rr.type === RecordType.RRSIG
				|| rr.type === RecordType.SIG) {
				continue;
			}

			// No special records.
			if (rr.type === RecordType.OPT
				|| rr.type === RecordType.TSIG) {
				continue;
			}

			set.add(rr.type);
		}
	}

	// Some kind of error.
	// Verify elsewhere.
	if (set.size === 0)
		return true;

	for (const rr of section) {
		if (rr.type !== RecordType.RRSIG)
			continue;

		const s = rr.data;
		const dnskey = zskMap.get(s.keyTag);

		if (!dnskey)
			continue; // Missing DNS Key

		if (!s.validityPeriod())
			continue; // Invalid Signature Period

		const rrset = extractSet(section, rr.name, s.typeCovered);

		if (rrset.length === 0)
			continue; // Missing Signed

		if (!verify(rr, dnskey, rrset))
			continue; // Invalid Signature

		set.delete(s.typeCovered);
	}

	if (set.size !== 0)
		return false; // Unsigned Data

	return true;
}

export function filterMessage(msg, type) {
	assert(msg instanceof Message);
	assert((type & 0xffff) === type);

	msg.answer = filterSection(msg.answer, type);
	msg.authority = filterSection(msg.authority, type);
	msg.additional = filterSection(msg.additional, type);

	return msg;
}

export function filterSection(section, type) {
	assert(Array.isArray(section));
	assert((type & 0xffff) === type);

	const filtered = [];

	for (const rr of section) {
		assert(rr instanceof Record);

		switch (rr.type) {
			case RecordType.DS:
			case RecordType.DLV:
			case RecordType.DNSKEY:
			case RecordType.RRSIG:
			case RecordType.NXT:
			case RecordType.NSEC:
			case RecordType.NSEC3:
			case RecordType.NSEC3PARAM:
				if (type !== rr.type)
					break;
			// fall through
			default:
				filtered.push(rr);
				break;
		}
	}

	return filtered;
}

/*
 * Helpers
 */

function compare(a, b) {
	const [ao] = readName(a, 0);
	const [bo] = readName(b, 0);
	const ab = a.slice(ao + 10);
	const bb = b.slice(bo + 10);
	return ab.compare(bb);
}

/*
 * Expose
 */

export {KeyFlag};
export {EncAlg};
export {HashAlg};
export {algHashes};
