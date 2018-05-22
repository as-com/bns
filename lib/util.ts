/*!
 * util.js - utils for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/labels.go
 *   https://github.com/miekg/dns/blob/master/dnsutil/util.go
 */

/* eslint spaced-comment: 0 */

'use strict';

import * as assert from "assert";
import IP from "binet";
import {sizeName} from "./encoding";
import {Record, RecordType} from "./wire";

export function splitName(s: string) {
	// assert(typeof s === 'string');

	if (s.length === 0)
		return [];

	const idx = split(s);
	const labels = [];

	let fend = 0;
	let begin = 0;

	if (s[s.length - 1] === '.')
		fend = s.length - 1;
	else
		fend = s.length;

	switch (idx.length) {
		case 0: {
			return [];
		}
		case 1: {
			break;
		}
		default: {
			let end = 0;
			for (let i = 1; i < idx.length; i++) {
				end = idx[i];
				labels.push(s.substring(begin, end - 1));
				begin = end;
			}
			break;
		}
	}

	labels.push(s.substring(begin, fend));

	return labels;
}

export function compareName(s1: string, s2: string) {
	// assert(typeof s1 === 'string');
	// assert(typeof s2 === 'string');

	let n = 0;

	if (s1 === '.' || s2 === '.')
		return 0;

	const l1 = split(s1);
	const l2 = split(s2);

	let j1 = l1.length - 1;
	let i1 = l1.length - 2;

	let j2 = l2.length - 1;
	let i2 = l2.length - 2;

	const a = s1.substring(l1[j1]);
	const b = s2.substring(l2[j2]);

	if (!equal(a, b))
		return n;

	n += 1;

	for (; ;) {
		if (i1 < 0 || i2 < 0)
			break;

		const a = s1.substring(l1[i1], l1[j1]);
		const b = s2.substring(l2[i2], l2[j2]);

		if (!equal(a, b))
			break;

		n += 1;

		j1 -= 1;
		i1 -= 1;

		j2 -= 1;
		i2 -= 1;
	}

	return n;
}

export function countLabels(s: string) {
	// assert(typeof s === 'string');

	let labels = 0;

	if (s === '.')
		return labels;

	let off = 0;
	let end = false;

	for (; ;) {
		[off, end] = nextLabel(s, off);

		labels += 1;

		if (end)
			break;
	}

	return labels;
}

export function split(s: string) {
	// assert(typeof s === 'string');

	if (s === '.')
		return [];

	const idx = [0];

	let off = 0;
	let end = false;

	for (; ;) {
		[off, end] = nextLabel(s, off);

		if (end)
			break;

		idx.push(off);
	}

	return idx;
}

export function nextLabel(s: string, off: number): [number, boolean] {
	// assert(typeof s === 'string');
	// assert(typeof off === 'number');

	let escaped = false;
	let i = 0;

	for (i = off; i < s.length - 1; i++) {
		const ch = s.charCodeAt(i);

		switch (ch) {
			case 0x5c /*\\*/
			:
				escaped = !escaped;
				break;
			case 0x2e /*.*/
			:
				if (escaped) {
					escaped = !escaped;
					continue;
				}
				return [i + 1, false];
			default:
				escaped = false;
				break;
		}
	}

	return [i + 1, true];
}

export function prevLabel(s: string, n: number): [number, boolean] {
	// assert(typeof s === 'string');
	// assert(typeof n === 'number');

	if (n === 0)
		return [s.length, false];

	const lab = split(s);

	if (lab.length === 0)
		return [0, true];

	if (n > lab.length)
		return [0, true];

	return [lab[lab.length - n], false];
}

export function equal(a: string, b: string) {
	// assert(typeof a === 'string');
	// assert(typeof b === 'string');

	if (a.length !== b.length)
		return false;

	for (let i = a.length - 1; i >= 0; i--) {
		let x = a.charCodeAt(i);
		let y = b.charCodeAt(i);

		if (x >= 0x41 && x <= 0x5a)
			x |= 0x20;

		if (y >= 0x41 && y <= 0x5a)
			y |= 0x20;

		if (x !== y)
			return false;
	}

	return true;
}

export function compare(a: string, b: string) {
	// assert(typeof a === 'string');
	// assert(typeof b === 'string');

	const len = Math.min(a.length, b.length);

	for (let i = 0; i < len; i++) {
		let x = a.charCodeAt(i);
		let y = b.charCodeAt(i);

		if (x >= 0x41 && x <= 0x5a)
			x |= 0x20;

		if (y >= 0x41 && y <= 0x5a)
			y |= 0x20;

		if (x < y)
			return -1;

		if (x > y)
			return 1;
	}

	if (a.length < b.length)
		return -1;

	if (a.length > b.length)
		return 1;

	return 0;
}

export function isName(s: string) {
	// assert(typeof s === 'string');

	try {
		sizeName(fqdn(s), null, false);
		return true;
	} catch (e) {
		return false;
	}
}

export function isFQDN(s: string) {
	// assert(typeof s === 'string');

	if (s.length === 0)
		return false;

	return s.charCodeAt(s.length - 1) === 0x2e /*.*/;
}

export function fqdn(s: string) {
	if (isFQDN(s))
		return s;

	return s + '.';
}

export function trimFQDN(s: string) {
	if (!isFQDN(s))
		return s;

	return s.slice(0, -1);
}

export function isSubdomain(parent: string, child: string) {
	return compareName(parent, child) === countLabels(parent);
}

export function addOrigin(s: string, origin: string) {
	// assert(typeof s === 'string');
	// assert(typeof origin === 'string');

	if (isFQDN(s))
		return s;

	if (origin.length === 0)
		return false;

	if (s === '@' || s.length === 0)
		return origin;

	if (origin === '.')
		return fqdn(s);

	return `${s}.${origin}`;
}

export function trimDomainName(s: string, origin: string) {
	// assert(typeof s === 'string');
	// assert(typeof origin === 'string');

	if (s.length === 0)
		return '@';

	if (origin === '.')
		return trimFQDN(s);

	const original = s;

	s = fqdn(s);
	origin = fqdn(origin);

	if (!isSubdomain(origin, s))
		return original;

	const slabels = split(s);
	const olabels = split(origin);
	const m = compareName(s, origin);

	if (olabels.length === m) {
		if (olabels.length === slabels.length)
			return '@';

		if (s[0] === '.' && slabels.length === olabels.length + 1)
			return '@';
	}

	return s.substring(0, slabels[slabels.length - m] - 1);
}

export function label(s: string, index: number);
export function label(s: string, labels: number[], index: number);
export function label(s: string, labels: number | number[], index?: number) {
	if (typeof labels === 'number') {
		index = labels;
		labels = split(s);
	}

	// assert(typeof s === 'string');
	// assert(Array.isArray(labels));
	// assert(typeof index === 'number');

	if (index < 0)
		index += labels.length;

	if (index >= labels.length)
		return '';

	const start = labels[index];

	if (index + 1 === labels.length) {
		if (isFQDN(s))
			return s.slice(start, -1);
		return s.substring(start);
	}

	const end = labels[index + 1];

	return s.substring(start, end - 1);
}

export function from(s: string, labels: number);
export function from(s: string, labels: number[], index: number);
export function from(s: string, labels: number | number[], index?: number) {
	if (typeof labels === 'number') {
		index = labels;
		labels = split(s);
	}

	// assert(typeof s === 'string');
	// assert(Array.isArray(labels));
	// assert(typeof index === 'number');

	if (index < 0)
		index += labels.length;

	if (index >= labels.length)
		return '';

	return s.substring(labels[index]);
}

export function to(s: string, index: number);
export function to(s: string, labels: number[], index: number);
export function to(s: string, labels: number | number[], index?: number) {
	if (typeof labels === 'number') {
		index = labels;
		labels = split(s);
	}

	// assert(typeof s === 'string');
	// assert(Array.isArray(labels));
	// assert(typeof index === 'number');

	if (index < 0)
		index += labels.length;

	if (index >= labels.length)
		return '';

	return s.substring(0, labels[index]);
}

export function startsWith(s: string, pre: string) {
	// assert(typeof s === 'string');
	// assert(typeof pre === 'string');

	if (s.startsWith)
		return s.startsWith(pre);

	if (pre.length === 0)
		return true;

	if (s.length === 0)
		return false;

	if (pre.length > s.length)
		return false;

	if (pre.length === 1)
		return s[0] === pre;

	return s.substring(0, pre.length) === pre;
}

export function endsWith(s: string, suf: string) {
	// assert(typeof s === 'string');
	// assert(typeof suf === 'string');

	if (s.endsWith)
		return s.endsWith(suf);

	if (suf.length === 0)
		return true;

	if (s.length === 0)
		return false;

	if (suf.length > s.length)
		return false;

	if (suf.length === 1)
		return s[s.length - 1] === suf;

	return s.slice(-suf.length) === suf;
}

export function trimPrefix(s: string, pre: string) {
	if (startsWith(s, pre))
		return s.slice(pre.length);
	return s;
}

export function trimSuffix(s: string, suf: string) {
	if (endsWith(s, suf))
		return s.slice(0, -suf.length);
	return s;
}

export function isRRSet(rrset: any[]) {
	assert(Array.isArray(rrset));

	if (rrset.length === 0)
		return false;

	if (rrset.length === 1)
		return true;

	const type = rrset[0].type;
	const class_ = rrset[0].class;
	const name = rrset[0].name;

	for (let i = 1; i < rrset.length; i++) {
		const rr = rrset[i];

		if (rr.type !== type
			|| rr.class !== class_
			|| !equal(rr.name, name)) {
			return false;
		}
	}

	return true;
}

export function filterSet(records: Record[], ...types: RecordType[]) {
	// assert(Array.isArray(records));

	const set = new Set(types);
	const out = [];

	for (const rr of records) {
		if (!set.has(rr.type))
			out.push(rr);
	}

	return out;
}

export function extractSet(records: Record[], name: string, ...types: RecordType[]) {
	// assert(Array.isArray(records));
	// assert(typeof name === 'string');

	const set = new Set(types);
	const out = [];

	for (const rr of records) {
		if (set.has(rr.type)) {
			if (name !== '' && !equal(rr.name, name))
				continue;
			out.push(rr);
		}
	}

	return out;
}

export function hasType(records: Record[], type: RecordType) {
	// assert(Array.isArray(records));
	// assert(typeof type === 'number');

	for (const rr of records) {
		if (rr.type === type)
			return true;
	}

	return false;
}

export function hasAll(records: Record[], type: RecordType) {
	// assert(Array.isArray(records));
	// assert(typeof type === 'number');

	for (const rr of records) {
		if (rr.type !== type)
			return false;
	}

	return true;
}

export function random(n: number) {
	// assert(typeof n === 'number');
	return Math.floor(Math.random() * n);
}

export function randomItem<T>(items: T[]) {
	assert(Array.isArray(items));
	return items[random(items.length)];
}

export function now() {
	return Math.floor(Date.now() / 1000);
}

export function digDate(time: number) {
	let date;

	if (time != null) {
		assert(Number.isSafeInteger(time));
		assert(time >= 0);
		date = new Date(time * 1000);
	} else {
		date = new Date();
	}

	const str = date.toString();
	const parts = str.split(' ');
	const [n, m, d, y, t, , tz] = parts;
	const z = tz.slice(1, -1);

	return `${n} ${m} ${d} ${t} ${z} ${y}`;
}

export function parseInteger(str: string, max: number, size: number) {
	// assert(typeof str === 'string');

	let word = 0;

	if (str.length === 0 || str.length > size)
		throw new Error('Invalid integer.');

	for (let i = 0; i < str.length; i++) {
		const ch = str.charCodeAt(i) - 0x30;

		if (ch < 0 || ch > 9)
			throw new Error('Invalid integer.');

		word *= 10;
		word += ch;

		if (word > max)
			throw new Error('Invalid integer.');
	}

	return word;
}

export function parseU8(str: string) {
	return parseInteger(str, 0xff, 3);
}

export function parseU16(str: string) {
	return parseInteger(str, 0xffff, 5);
}

export function parseU32(str: string) {
	return parseInteger(str, 0xffffffff, 10);
}

export function parseU48(str: string) {
	return parseInteger(str, 0xffffffffffff, 15);
}

export function parseU64(str: string) {
	// assert(typeof str === 'string');

	if (str.length === 0 || str.length > 20)
		throw new Error('Invalid integer.');

	let hi = 0;
	let lo = 0;

	for (let i = 0; i < str.length; i++) {
		const ch = str.charCodeAt(i) - 0x30;

		if (ch < 0 || ch > 9)
			throw new Error('Invalid integer.');

		lo *= 10;
		lo += ch;

		hi *= 10;

		if (lo > 0xffffffff) {
			const m = lo % 0x100000000;
			hi += (lo - m) / 0x100000000;
			lo = m;
		}

		if (hi > 0xffffffff)
			throw new Error('Invalid integer.');
	}

	return [hi, lo];
}

export function serializeU64(hi: number, lo: number) {
	assert((hi >>> 0) === hi);
	assert((lo >>> 0) === lo);

	let str = '';

	do {
		const mhi = hi % 10;
		hi -= mhi;
		hi /= 10;
		lo += mhi * 0x100000000;

		const mlo = lo % 10;
		lo -= mlo;
		lo /= 10;

		const ch = mlo + 0x30;

		str = String.fromCharCode(ch) + str;
	} while (lo > 0 || hi > 0);

	return str;
}

export function dir(obj: any, inspect: boolean = true) {
	console.dir(obj, {
		depth: 20,
		colors: true,
		customInspect: inspect
	});
}

export function isIP(host: string) {
	return IP.test(host) !== 0;
}

export function id() {
	return (Math.random() * 0x10000) >>> 0;
}

export function cookie() {
	const buf = Buffer.allocUnsafe(8);
	const hi = (Math.random() * 0x100000000) >>> 0;
	const lo = (Math.random() * 0x100000000) >>> 0;
	buf.writeUInt32LE(lo, 0, true);
	buf.writeUInt32LE(hi, 4, true);
	return buf;
}

export function sortRandom<T>(items: T[]) {
	assert(Array.isArray(items));

	if (items.length <= 1)
		return items;

	return items.slice().sort(() => {
		return Math.random() > 0.5 ? 1 : -1;
	});
}

export function ensureLF(str: string) {
	// assert(typeof str === 'string');

	str = str.replace(/\r\n/g, '\n');
	str = str.replace(/\r/g, '\n');

	return str;
}

export function ensureSP(str: string) {
	// assert(typeof str === 'string');
	return str.replace(/[ \t\v]/g, ' ');
}

export function splitLF(str: string, limit?: number) {
	// assert(typeof str === 'string');
	if (limit === null)
		limit = undefined;
	return str.trim().split(/\n+/, limit);
}

export function splitSP(str: string, limit?: number) {
	// assert(typeof str === 'string');
	if (limit === null)
		limit = undefined;
	return str.trim().split(/[ \t\v]+/, limit);
}

export function stripBOM(str: string) {
	// assert(typeof str === 'string');

	if (str.length === 0)
		return str;

	if (str.charCodeAt(0) !== 0xfeff)
		return str;

	return str.substring(1);
}

export function stripSP(str: string) {
	// assert(typeof str === 'string');
	return str.replace(/[ \t\v]+/g, '');
}

export function stripLF(str: string) {
	// assert(typeof str === 'string');
	return str.replace(/\n+/g, '');
}

export function splitLines(str: string, escaped?: boolean, limit?: number) {
	// assert(typeof str === 'string');

	str = stripBOM(str);
	str = ensureLF(str);
	str = ensureSP(str);

	if (escaped)
		str = str.replace(/\\\n/g, '');

	const lines = splitLF(str, limit);
	const out = [];

	for (const chunk of lines) {
		const line = chunk.trim();

		if (line.length === 0)
			continue;

		out.push(line);
	}

	return out;
}

export function isHex(str: string) {
	// assert(typeof str === 'string');

	if (str.length & 1)
		return false;

	return /^[A-Fa-f0-9]+$/.test(str);
}

export function parseHex(str: string) {
	// assert(typeof str === 'string');

	if (str.length & 1)
		throw new Error('Invalid hex string.');

	const data = Buffer.from(str, 'hex');

	if (data.length !== (str.length >>> 1))
		throw new Error('Invalid hex string.');

	return data;
}

export function isB64(str: string) {
	// assert(typeof str === 'string');
	return /^[A-Za-z0-9+\/=]+$/.test(str);
}

export function parseB64(str: string) {
	// assert(typeof str === 'string');

	const min = (((str.length - 3) & ~3) * 3) / 4 | 0;
	const data = Buffer.from(str, 'base64');

	if (data.length < min)
		throw new Error('Invalid base64 string.');

	return data;
}

export function padRight(data: Buffer, size: number) {
	// assert(Buffer.isBuffer(data));
	assert((size >>> 0) === size);

	if (data.length < size) {
		const buf = Buffer.allocUnsafe(size);
		data.copy(buf, 0);
		buf.fill(0x00, data.length, size);
		return buf;
	}

	if (data.length > size)
		return data.slice(0, size);

	return data;
}
