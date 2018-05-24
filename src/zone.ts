/*!
 * hints.ts - root hints object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

import * as assert from "assert";
import * as fs from "bfile";
import {Code, RecordType} from "./constants";
import * as util from "./util";
import * as wire from "./wire";
import {AAAARecord, ARecord, Message, NSRecord, Record} from "./wire";
/*
 * Constants
 */
import ROOT_HINTS from "./roothints";

/*
 * Cache
 */

let hints = null;

/**
 * Zone
 */

class Zone {
	origin: string;
	count: number;
	names: Map<string, RecordMap>;
	wild: RecordMap;
	nsec: NameList;

	constructor(origin?) {
		this.origin = '.';
		this.count = 0;
		this.names = new Map();
		this.wild = new RecordMap();
		this.nsec = new NameList();
		this.setOrigin(origin);
	}

	clear() {
		this.origin = '.';
		this.count = 0;
		this.clearRecords();
		return this;
	}

	clearRecords() {
		this.names.clear();
		this.wild.clear();
		this.nsec.clear();
		return this;
	}

	setOrigin(origin) {
		if (origin == null)
			origin = '.';

		assert(util.isFQDN(origin));

		this.origin = origin.toLowerCase();
		this.count = util.countLabels(this.origin);

		return this;
	}

	insert(record) {
		assert(record instanceof Record);

		const rr = record.deepClone();

		// Lowercase.
		rr.canonical();

		if (rr.type !== RecordType.A && rr.type !== RecordType.AAAA) {
			if (!util.isSubdomain(this.origin, rr.name))
				throw new Error('Not a child of this zone.');
		}

		if (isWild(rr.name)) {
			this.wild.insert(rr);
		} else {
			if (!this.names.has(rr.name))
				this.names.set(rr.name, new RecordMap());

			const map = this.names.get(rr.name);

			map.insert(rr);
		}

		switch (rr.type) {
			case RecordType.NSEC: {
				this.nsec.insert(rr.name);
				break;
			}
		}

		return this;
	}

	push(name: string, type: number, an: Record[], ns?) {
		assert(util.isFQDN(name));
		assert((type & 0xffff) === type);
		// assert(Array.isArray(an));

		const map = this.names.get(name);

		if (map)
			map.push(name, type, an);

		this.wild.push(name, type, an);

		return this;
	}

	get(name: string, type: number) {
		const an: Record[] = [];
		this.push(name, type, an);
		return an;
	}

	glue(name: string, an: Record[]) {
		assert(util.isFQDN(name));
		// assert(Array.isArray(an));

		this.push(name, RecordType.A, an);
		this.push(name, RecordType.AAAA, an);

		return this;
	}

	find(name: string, type: number): [Record<any>[], Record[]] {
		const an: Record<any>[] = this.get(name, type);
		const ar: Record[] = [];

		for (const rr of an) {
			switch (rr.type) {
				case RecordType.CNAME:
					this.glue(rr.data.target, an);
					break;
				case RecordType.DNAME:
					this.glue(rr.data.target, an);
					break;
				case RecordType.NS:
					this.glue(rr.data.ns, ar);
					break;
				case RecordType.SOA:
					this.glue(rr.data.ns, ar);
					break;
				case RecordType.MX:
					this.glue(rr.data.mx, ar);
					break;
				case RecordType.SRV:
					this.glue(rr.data.target, ar);
					break;
			}
		}

		return [an, ar];
	}

	getHints(): [Record<NSRecord>[], Record<ARecord | AAAARecord>[]] {
		if (!hints) {
			hints = wire.fromZone(ROOT_HINTS, '.');
			for (const rr of hints)
				rr.canonical();
		}

		const ns: Record<NSRecord>[] = [];
		const ar: Record<ARecord | AAAARecord>[] = [];

		for (const rr of hints) {
			switch (rr.type) {
				case RecordType.NS:
					ns.push(rr);
					break;
				case RecordType.A:
				case RecordType.AAAA:
					ar.push(rr);
					break;
			}
		}

		return [ns, ar];
	}

	proveNoData(ns) {
		this.push(this.origin, RecordType.NSEC, true as any, ns); // TODO???
		return this;
	}

	proveNameError(name, ns) {
		const lower = this.nsec.lower(name);

		if (lower)
			this.push(lower, RecordType.NSEC, true as any, ns); // TODO????

		this.proveNoData(ns);

		return this;
	}

	query(name: string, type: number): [Record<any>[], Record<any>[], Record<any>[], boolean, boolean] {
		assert(util.isFQDN(name));
		assert((type & 0xffff) === type);

		const [an, ar] = this.find(name, type);

		if (an.length > 0) {
			const aa = util.equal(name, this.origin);
			return [an, [], ar, aa, true];
		}

		const labels = util.split(name);

		if (this.origin !== '.') {
			const zone = util.from(name, labels, -this.count);

			// Refer them back to the root zone.
			if (this.origin !== zone) {
				const [ns, ar] = this.getHints();
				return [[], ns, ar, false, true];
			}
		}

		// Serve an SoA (no data).
		if (labels.length === this.count) {
			const ns = this.get(this.origin, RecordType.SOA);
			this.proveNoData(ns);
			return [[], ns, [], true, false];
		}

		const index = this.count + 1;
		const child = util.from(name, labels, -index);
		const [ns, glue] = this.find(child, RecordType.NS);

		// Serve an SoA (nxdomain).
		if (ns.length === 0) {
			const ns = this.get(this.origin, RecordType.SOA);
			this.proveNameError(child, ns);
			return [[], ns, [], false, false];
		}

		this.push(child, RecordType.DS, ns);

		return [[], ns, glue, false, true];
	}

	resolve(name, type) {
		assert(util.isFQDN(name));
		assert((type & 0xffff) === type);

		const qname = name.toLowerCase();
		const qtype = type === RecordType.ANY ? RecordType.NS : type;
		const [an, ns, ar, aa, ok] = this.query(qname, qtype);
		const msg = new Message();

		if (!aa && !ok)
			msg.code = Code.NXDOMAIN;

		msg.aa = aa;
		msg.answer = an;
		msg.authority = ns;
		msg.additional = ar;

		return msg;
	}

	fromString(text, file) {
		const rrs = wire.fromZone(text, this.origin, file);

		for (const rr of rrs)
			this.insert(rr);

		return this;
	}

	static fromString(origin, text, file) {
		return new this(origin).fromString(text, file);
	}

	fromFile(file) {
		const text = fs.readFileSync(file, 'utf8');
		return this.fromString(text, file);
	}

	static fromFile(origin, file) {
		return new this(origin).fromFile(file);
	}
}

/**
 * RecordMap
 */

export class RecordMap {
	rrs: Map<RecordType, Record[]>;
	sigs: Map<number, Record[]>;

	constructor() {
		// type -> rrs
		this.rrs = new Map();
		// type covered -> sigs
		this.sigs = new Map();
	}

	clear() {
		this.rrs.clear();
		this.sigs.clear();
		return this;
	}

	insert(rr: Record) {
		// assert(rr instanceof Record);

		if (!this.rrs.has(rr.type))
			this.rrs.set(rr.type, []);

		const rrs = this.rrs.get(rr.type);

		rrs.push(rr);

		switch (rr.type) {
			case RecordType.RRSIG: {
				const {typeCovered} = rr.data;

				if (!this.sigs.has(typeCovered))
					this.sigs.set(typeCovered, []);

				const sigs = this.sigs.get(typeCovered);
				sigs.push(rr);

				break;
			}
		}

		return this;
	}

	push(name: string, type: number, an: Record[]) {
		assert(util.isFQDN(name));
		assert((type & 0xffff) === type);
		// assert(Array.isArray(an));

		const rrs = this.rrs.get(type);

		if (!rrs || rrs.length === 0)
			return this;

		for (const rr of rrs)
			an.push(convert(name, rr));

		const sigs = this.sigs.get(type);

		if (sigs) {
			for (const rr of sigs)
				an.push(convert(name, rr));
		}

		return this;
	}

	get(name, type) {
		const an = [];
		this.push(name, type, an);
		return an;
	}
}

/**
 * NameList
 */

export class NameList {
	private names: any[];

	constructor() {
		this.names = [];
	}

	clear() {
		this.names.length = 0;
		return this;
	}

	insert(name) {
		return insertString(this.names, name);
	}

	lower(name) {
		return findLower(this.names, name);
	}
}

/*
 * Helpers
 */

function search(items, key, compare, insert) {
	let start = 0;
	let end = items.length - 1;

	while (start <= end) {
		const pos = (start + end) >>> 1;
		const cmp = compare(items[pos], key);

		if (cmp === 0)
			return pos;

		if (cmp < 0)
			start = pos + 1;
		else
			end = pos - 1;
	}

	if (!insert)
		return -1;

	return start;
}

function insert(items, item, compare, uniq) {
	const i = search(items, item, compare, true);

	if (uniq && i < items.length) {
		if (compare(items[i], item) === 0)
			return -1;
	}

	if (i === 0)
		items.unshift(item);
	else if (i === items.length)
		items.push(item);
	else
		items.splice(i, 0, item);

	return i;
}

function insertString(items, name: string) {
	assert(Array.isArray(items));
	// assert(typeof name === 'string');

	return insert(items, name, util.compare, true) !== -1;
}

function findLower(items, name) {
	assert(Array.isArray(items));
	assert(typeof name === 'string');

	if (items.length === 0)
		return null;

	const i = search(items, name, util.compare, true);
	const match = items[i];
	const cmp = util.compare(match, name);

	if (cmp === 0)
		throw new Error('Not an NXDOMAIN.');

	if (cmp < 0)
		return match;

	if (i === 0)
		return null;

	return items[i - 1];
}

function isWild(name: string) {
	// assert(typeof name === 'string');
	if (name.length < 2)
		return false;
	return name[0] === '*' && name[1] === '.';
}

function convert(name: string, rr: Record) {
	if (!isWild(rr.name))
		return rr;

	const x = util.splitName(name);
	const y = util.splitName(rr.name);

	assert(y.length > 0);

	if (x.length < y.length)
		return rr;

	rr = rr.clone() as Record;

	y[0] = x[x.length - y.length];

	rr.name = `${y.join('.')}.`;

	return rr;
}

/*
 * Expose
 */

export default Zone;
