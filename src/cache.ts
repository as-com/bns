/*!
 * cache.js - resolver cache for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

import * as assert from "assert";
import * as Heap from "bheep";
import * as wire from "./wire";
import {Message, Question} from "./wire";
import * as util from "./util";

/**
 * Cache
 */

export default class Cache {
	map = new Map<string, CacheEntry>();
	queue = new Heap((a, b) => a[1] - b[1]);
	size = 0;
	maxSize = 5 << 20;

	get(id: string) {
		return this.map.get(id) || null;
	}

	has(id: string) {
		return this.map.has(id);
	}

	set(id: string, entry: CacheEntry) {
		this.map.set(id, entry);
		return this;
	}

	remove(id: string) {
		this.map.delete(id);
		return this;
	}

	hash(qs: Question, zone: string) {
		const n = qs.name.toLowerCase();
		const t = qs.type.toString(10);
		const z = zone.toLowerCase();
		return `${n};${t};${z}`;
	}

	prune() {
		while (this.size > this.maxSize) {
			const [id, deadline] = this.queue.shift();
			const entry = this.get(id);

			if (entry && entry.deadline() === deadline) {
				this.size -= entry.usage(id);
				this.remove(id);
			}

			this.size -= queueUsage(id);
		}

		return this;
	}

	insert(qs: Question, zone: string, msg: Message, ad: boolean, eternal = false) {
		// assert(qs instanceof Question);
		// assert(typeof zone === 'string');
		// assert(msg instanceof Message);
		// assert(typeof ad === 'boolean');
		// assert(typeof eternal === 'boolean');

		const id = this.hash(qs, zone);
		const ttl = msg.minTTL();

		if (ttl === 0)
			return this;

		const item = this.get(id);

		if (item) {
			if (item.eternal)
				return this;

			const raw = msg.encode();

			this.size -= item.usage(id);

			item.msg = raw;
			item.setAD(ad);
			item.time = util.now();
			item.ttl = ttl;

			this.size += item.usage(id);

			this.size += queueUsage(id);
			this.queue.insert([id, item.deadline()]);
			this.prune();

			return this;
		}

		const raw = msg.encode();
		const entry = new CacheEntry(raw);

		entry.setAD(ad);
		entry.time = util.now();
		entry.ttl = ttl;
		entry.eternal = eternal;

		this.set(id, entry);
		this.size += entry.usage(id);

		if (!eternal) {
			this.size += queueUsage(id);
			this.queue.insert([id, entry.deadline()]);
			this.prune();
		}

		return this;
	}

	hit(qs: Question, zone: string) {
		// assert(qs instanceof Question);
		// assert(typeof zone === 'string');

		const id = this.hash(qs, zone);
		const entry = this.get(id);

		if (!entry)
			return null;

		const now = util.now();

		if (entry.expired(now)) {
			this.size -= entry.usage(id);
			this.remove(id);
			return null;
		}

		const msg = Message.decode<Message>(entry.msg);
		const diff = now - entry.time;

		assert(diff >= 0);

		for (const rr of msg.records()) {
			if (rr.isOPT())
				continue;

			if (rr.ttl === 0)
				continue;

			if (rr.ttl <= diff) {
				rr.ttl = 1;
				continue;
			}

			rr.ttl -= diff;
		}

		return msg;
	}
}

/**
 * CacheEntry
 */

export class CacheEntry {
	msg: Buffer;
	time: number;
	ttl: number;
	eternal: boolean;

	constructor(msg: Buffer) {
		// assert(Buffer.isBuffer(msg));
		this.msg = msg;
		this.time = 0;
		this.ttl = 0;
		this.eternal = false;
	}

	deadline() {
		if (this.eternal)
			return 0xffffffff;

		return this.time + this.ttl;
	}

	usage(id: string) {
		let size = 0;
		size += id.length * 2;
		size += 80 + this.msg.length;
		size += 8 * 3;
		return size;
	}

	setAD(ad: boolean) {
		let bits = this.msg.readUInt16BE(2, true);

		if (ad)
			bits |= wire.Flag.AD;
		else
			bits &= ~wire.Flag.AD;

		this.msg.writeUInt16BE(bits, 2, true);
	}

	expired(now: number) {
		// Someone changed
		// their system time.
		// Clear cache.
		if (now < this.time)
			return true;

		if (this.eternal)
			return false;

		return now >= this.deadline();
	}
}

/*
 * Helpers
 */

function queueUsage(id: string) {
	return id.length * 2 + 20;
}
