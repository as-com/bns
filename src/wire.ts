/*!
 * wire.js - wire types for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/miekg/dns/blob/master/edns.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 */

'use strict';

import * as assert from "assert";
import * as bio from "@as-com/bufio";
import {BufferReader, Struct} from "@as-com/bufio";
import * as IP from "binet";
import {
	algHashes,
	algToString,
	CertType,
	classToString,
	Code,
	codeToString,
	DaneMatchingType,
	DaneSelector,
	DaneUsage,
	DEFAULT_TTL,
	DNS_PORT,
	EFlag,
	EncAlg,
	EOption,
	Flag,
	HashAlg,
	hashToString,
	isAlgString,
	isClassString,
	isCodeString,
	isHashString,
	isOpcodeString,
	isOptionString,
	isTypeString,
	KeyFlag,
	LOC_ALTITUDEBASE,
	LOC_DEGREES,
	LOC_EQUATOR,
	LOC_HOURS,
	LOC_PRIMEMERIDIAN,
	MAX_EDNS_SIZE,
	MAX_LABEL_SIZE,
	MAX_MSG_SIZE,
	MAX_NAME_SIZE,
	MAX_UDP_SIZE,
	NsecHash,
	Opcode,
	opcodeToString,
	optionToString,
	QuestionClass,
	RecordType,
	SSHAlg,
	SSHHash,
	STD_EDNS_SIZE,
	stringToAlg,
	stringToClass,
	stringToCode,
	stringToHash,
	stringToOpcode,
	stringToOption,
	stringToType,
	TKeyMode,
	TSigAlg,
	tsigAlgsByVal,
	typeToString,
	YEAR68
} from "./constants";
import * as encoding from "./encoding";
import {
	fromBitmap,
	hasType,
	readIP,
	readNameBR,
	readRawStringBR,
	readStringBR,
	sizeName,
	sizeRawString,
	sizeString,
	toBitmap,
	writeIP,
	writeNameBW,
	writeRawStringBW,
	writeStringBW
} from "./encoding";
import lazy from "./lazy";
import * as util from "./util";


/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DUMMY4 = Buffer.alloc(4);
const DUMMY6 = Buffer.alloc(6);
const DUMMY8 = Buffer.alloc(8);
const POOL16 = Buffer.allocUnsafe(16);

/**
 * Record Classes
 * @const {Object}
 */

let records = {};

/**
 * Record Classes By Value
 * @const {Object}
 */

let recordsByVal = {};

/**
 * EDNS0 Option Classes
 * @const {Object}
 */

let opts = {};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

let optsByVal = {};

/**
 * Message
 */

class Message extends Struct {
	id: number;
	flags: number;
	opcode: Opcode;
	code: Code;
	question: Question[];
	answer: Record[];
	authority: Record[];
	additional: Record[];
	edns: EDNS;
	tsig: Record | null;
	sig0: Record | null;
	size: number;
	malformed: boolean;
	trailing: Buffer;

	constructor() {
		super();

		this.id = 0;
		this.flags = 0;
		this.opcode = Opcode.QUERY;
		this.code = Code.NOERROR;
		this.question = [];
		this.answer = [];
		this.authority = [];
		this.additional = [];

		// Pseudo sections.
		this.edns = new EDNS();
		this.tsig = null;
		this.sig0 = null;

		// Extra properties.
		this.size = 0;
		this.malformed = false;
		this.trailing = DUMMY;
	}

	inject(msg: Struct): this {
		assert(msg instanceof Message);
		if (!(msg instanceof Message)) {
			return;
		}

		this.id = msg.id;
		this.flags = msg.flags;
		this.opcode = msg.opcode;
		this.code = msg.code;
		this.question = msg.question.slice();
		this.answer = msg.answer.slice();
		this.authority = msg.authority.slice();
		this.additional = msg.additional.slice();
		this.edns = msg.edns.clone();
		this.tsig = msg.tsig;
		this.sig0 = msg.sig0;
		this.size = msg.size;
		this.malformed = msg.malformed;
		this.trailing = msg.trailing;
		return this;
	}

	deepClone() {
		const msg = new Message();
		return msg.decode(this.encode());
	}

	refresh() {
		this.size = 0;
		this.malformed = false;
		this.trailing = DUMMY;
		return this;
	}

	sections() {
		return [
			this.answer,
			this.authority,
			this.additional
		];
	}

	* records() {
		for (const rr of this.answer)
			yield rr;

		for (const rr of this.authority)
			yield rr;

		for (const rr of this.additional)
			yield rr;
	}

	canonical() {
		for (const qs of this.question)
			qs.canonical();

		for (const rr of this.records())
			rr.canonical();

		this.edns.canonical();

		if (this.tsig)
			this.tsig.canonical();

		if (this.sig0)
			this.sig0.canonical();

		return this;
	}

	getFlag(bit) {
		return (this.flags & bit) !== 0;
	}

	setFlag(bit, value) {
		if (value)
			this.flags |= bit;
		else
			this.flags &= ~bit;

		return Boolean(value);
	}

	get qr() {
		return this.getFlag(Flag.QR);
	}

	set qr(value) {
		this.setFlag(Flag.QR, value);
	}

	get aa() {
		return this.getFlag(Flag.AA);
	}

	set aa(value) {
		this.setFlag(Flag.AA, value);
	}

	get tc() {
		return this.getFlag(Flag.TC);
	}

	set tc(value) {
		this.setFlag(Flag.TC, value);
	}

	get rd() {
		return this.getFlag(Flag.RD);
	}

	set rd(value) {
		this.setFlag(Flag.RD, value);
	}

	get ra() {
		return this.getFlag(Flag.RA);
	}

	set ra(value) {
		this.setFlag(Flag.RA, value);
	}

	get z() {
		return this.getFlag(Flag.Z);
	}

	set z(value) {
		this.setFlag(Flag.Z, value);
	}

	get ad() {
		return this.getFlag(Flag.AD);
	}

	set ad(value) {
		this.setFlag(Flag.AD, value);
	}

	get cd() {
		return this.getFlag(Flag.CD);
	}

	set cd(value) {
		this.setFlag(Flag.CD, value);
	}

	get qd() {
		return this.question;
	}

	set qd(value) {
		this.question = value;
	}

	get an() {
		return this.answer;
	}

	set an(value) {
		this.answer = value;
	}

	get ns() {
		return this.authority;
	}

	set ns(value) {
		this.authority = value;
	}

	get ar() {
		return this.additional;
	}

	set ar(value) {
		this.additional = value;
	}

	get qdcount() {
		return this.question.length;
	}

	get ancount() {
		return this.answer.length;
	}

	get nscount() {
		return this.authority.length;
	}

	get arcount() {
		let count = this.additional.length;

		if (this.edns.enabled)
			count += 1;

		if (this.tsig)
			count += 1;

		if (this.sig0)
			count += 1;

		return count;
	}

	setReply(req) {
		assert(req instanceof this.constructor);

		this.id = req.id;
		this.opcode = req.opcode;
		this.qr = true;

		if (this.opcode === Opcode.QUERY) {
			this.rd = req.rd;
			this.cd = req.cd;
		}

		this.question = [];

		if (req.question.length > 0)
			this.question.push(req.question[0]);

		return this;
	}

	isEDNS() {
		return this.edns.enabled;
	}

	setEDNS(size, dnssec) {
		assert((size & 0xffff) === size);
		assert(typeof dnssec === 'boolean');

		this.edns.reset();
		this.edns.enabled = true;
		this.edns.size = size;
		this.edns.dnssec = dnssec;

		if (this.code > 0x0f)
			this.edns.code = this.code >>> 4;

		return this;
	}

	unsetEDNS() {
		this.edns.reset();

		if (this.code > 0x0f)
			this.code = Code.NOERROR;

		return this;
	}

	isDNSSEC() {
		if (!this.edns.enabled)
			return false;

		return this.edns.dnssec;
	}

	maxSize(max) {
		if (max == null)
			max = MAX_EDNS_SIZE;

		assert((max & 0xffff) === max);
		assert(max >= MAX_UDP_SIZE && max <= MAX_EDNS_SIZE);

		if (this.edns.enabled
			&& this.edns.size >= MAX_UDP_SIZE) {
			return Math.min(max, this.edns.size);
		}

		return MAX_UDP_SIZE;
	}

	minTTL() {
		const now = util.now();

		let ttl = -1;

		for (const rr of this.records()) {
			if (rr.isOPT())
				continue;

			if (rr.ttl === 0)
				continue;

			if (ttl === -1 || rr.ttl < ttl)
				ttl = rr.ttl;

			if (rr.type === RecordType.RRSIG) {
				const rrr = rr as Record<RRSIGRecord>;
				const e = rrr.data.expiration;
				const t = e - now;

				if (t > 0 && t < ttl)
					ttl = t;
			}
		}

		if (ttl === -1)
			ttl = 0;

		return ttl;
	}

	isAnswer() {
		if (this.answer.length > 0
			&& (this.code === Code.NOERROR
				|| this.code === Code.YXDOMAIN
				|| this.code === Code.NXDOMAIN)) {
			return true;
		}

		return false;
	}

	isReferral() {
		if (this.isAnswer())
			return false;

		if (this.authority.length > 0
			&& (this.code === Code.NOERROR
				|| this.code === Code.YXDOMAIN)) {
			return true;
		}

		return false;
	}

	collect(name, type) {
		assert(typeof name === 'string');
		assert((type & 0xffff) === type);

		const result = [];

		let target = util.fqdn(name);

		for (const rr of this.answer) {
			if (!util.equal(rr.name, target))
				continue;

			if (rr.type === RecordType.CNAME) {
				let crr = rr as Record<CNAMERecord>;
				target = crr.data.target;

				if (type === RecordType.ANY
					|| type === RecordType.CNAME) {
					result.push(crr);
				}

				continue;
			}

			if (type !== RecordType.ANY) {
				if (rr.type !== type)
					continue;
			}

			result.push(rr);
		}

		return result;
	}

	getSize(map?) {
		let size = 12;

		for (const qs of this.question)
			size += qs.getSize(map);

		for (const rr of this.answer)
			size += rr.getSize(map);

		for (const rr of this.authority)
			size += rr.getSize(map);

		for (const rr of this.additional)
			size += rr.getSize(map);

		if (this.edns.enabled)
			size += this.edns.getSize(map);

		if (this.tsig)
			size += this.tsig.getSize(map);

		if (this.sig0)
			size += this.sig0.getSize(map);

		return size;
	}

	write(bw, map?): any {
		bw.writeU16BE(this.id);

		let bits = this.flags;

		bits &= ~(0x0f << 11);
		bits |= (this.opcode & 0x0f) << 11;

		bits &= ~0x0f;
		bits |= this.code & 0x0f;

		bw.writeU16BE(bits);
		bw.writeU16BE(this.question.length);
		bw.writeU16BE(this.answer.length);
		bw.writeU16BE(this.authority.length);
		bw.writeU16BE(this.arcount);

		for (const qs of this.question)
			qs.write(bw, map);

		for (const rr of this.answer)
			rr.write(bw, map);

		for (const rr of this.authority)
			rr.write(bw, map);

		for (const rr of this.additional)
			rr.write(bw, map);

		if (this.code > 0x0f) {
			this.edns.enabled = true;
			this.edns.code = this.code >>> 4;
		}

		if (this.edns.enabled)
			this.edns.write(bw, map);

		if (this.tsig)
			this.tsig.write(bw, map);

		if (this.sig0)
			this.sig0.write(bw, map);

		return this;
	}

	encode(max?: number) {
		const size = this.getSize();
		const bw = bio.write(size);

		this.write(bw, null);

		let msg = bw.render();

		if (max != null)
			msg = truncate(msg, max);

		if (msg.length > MAX_MSG_SIZE)
			throw new Error('Message exceeds size limits.');

		return msg;
	}

	compress(max) {
		const size = this.getSize();
		const bw = bio.write(size);
		const map = new Map();

		this.write(bw, map);

		let msg = bw.slice();

		if (max != null)
			msg = truncate(msg, max);

		if (msg.length > MAX_MSG_SIZE)
			throw new Error('Message exceeds size limits.');

		return msg;
	}

	read(br) {
		const size = br.data.length;
		const id = br.readU16BE();
		const bits = br.readU16BE();
		const qdcount = br.readU16BE();
		const ancount = br.readU16BE();
		const nscount = br.readU16BE();
		const arcount = br.readU16BE();

		this.size = size;
		this.id = id;
		this.flags = bits;
		this.flags &= ~(0x0f << 11);
		this.flags &= ~0x0f;
		this.opcode = (bits >>> 11) & 0x0f;
		this.code = bits & 0x0f;

		let tc = false;

		for (let i = 0; i < qdcount; i++) {
			if (br.left() === 0) {
				tc = true;
				break;
			}

			const qs = Question.read<Question>(br);

			this.question.push(qs);
		}

		for (let i = 0; i < ancount; i++) {
			if (br.left() === 0) {
				tc = true;
				break;
			}

			const rr = Record.read<Record>(br);

			this.answer.push(rr);
		}

		for (let i = 0; i < nscount; i++) {
			if (br.left() === 0) {
				tc = true;
				break;
			}

			const rr = Record.read<Record>(br);

			this.authority.push(rr);
		}

		for (let i = 0; i < arcount; i++) {
			if (br.left() === 0) {
				tc = true;
				break;
			}

			const rr = Record.read<Record>(br);

			if (rr.isOPT()) {
				this.edns.setRecord(rr);
				this.code &= 0x0f;
				this.code |= this.edns.code << 4;
				continue;
			}

			if (rr.isTSIG()) {
				this.tsig = rr;
				continue;
			}

			if (rr.isSIG0()) {
				this.sig0 = rr;
				continue;
			}

			this.additional.push(rr);
		}

		if (tc && !(bits & Flag.TC))
			this.malformed = true;

		if (br.left() > 0)
			this.trailing = br.readBytes(br.left());

		return this;
	}

	toShort(name, type) {
		const qs = new Question(name, type);
		const rrs = this.collect(qs.name, qs.type);

		let out = '';

		for (const rr of rrs) {
			out += rr.data.toString();
			out += '\n';
		}

		return out;
	}

	toString(ms?, host?, port?) {
		let diff = -1;
		let sec = -1;

		if (ms != null) {
			assert(Number.isSafeInteger(ms) && ms >= 0);
			diff = Math.max(0, Date.now() - ms);
			sec = Math.floor(ms / 1000);
		}

		if (host != null) {
			if (port == null)
				port = DNS_PORT;

			assert(typeof host === 'string');
			assert((port & 0xffff) === port);
		}

		const opcode = opcodeToString(this.opcode);
		const status = codeToString(this.code);
		const id = this.id.toString(10);
		const flags = [];

		if (this.qr)
			flags.push('qr');

		if (this.aa)
			flags.push('aa');

		if (this.tc)
			flags.push('tc');

		if (this.rd)
			flags.push('rd');

		if (this.ra)
			flags.push('ra');

		if (this.z)
			flags.push('z');

		if (this.ad)
			flags.push('ad');

		if (this.cd)
			flags.push('cd');

		let str = '';

		str += ';; ->>HEADER<<-';
		str += ` opcode: ${opcode}, status: ${status}, id: ${id}\n`;
		str += `;; flags: ${flags.join(' ')};`;
		str += ` QUERY: ${this.question.length},`;
		str += ` ANSWER: ${this.answer.length},`;
		str += ` AUTHORITY: ${this.authority.length},`;
		str += ` ADDITIONAL: ${this.arcount}\n`;

		if (this.edns.enabled) {
			const version = this.edns.version;
			const flags = this.edns.dnssec ? ' do' : '';
			const udp = this.edns.size;

			str += '\n';
			str += ';; OPT PSEUDOSECTION:\n';
			str += `; EDNS: version: ${version}, flags:${flags}; udp: ${udp}`;

			for (const opt of this.edns.options) {
				str += '\n';
				str += '; ';
				str += opt.toString();
			}
		}

		if (this.question.length > 0) {
			str += '\n';
			str += ';; QUESTION SECTION:\n';

			for (const qs of this.question) {
				str += ';';
				str += qs.toString();
				str += '\n';
			}
		}

		if (this.answer.length > 0) {
			str += '\n';
			str += ';; ANSWER SECTION:\n';

			for (const rr of this.answer) {
				str += rr.toString();
				str += '\n';
			}
		}

		if (this.authority.length > 0) {
			str += '\n';
			str += ';; AUTHORITY SECTION:\n';

			for (const rr of this.authority) {
				str += rr.toString();
				str += '\n';
			}
		}

		if (this.additional.length > 0) {
			str += '\n';
			str += ';; ADDITIONAL SECTION:\n';

			for (const rr of this.additional) {
				str += rr.toString();
				str += '\n';
			}
		}

		if (this.tsig) {
			str += '\n';
			str += ';; TSIG PSEUDOSECTION:\n';
			str += this.tsig.toString();
			str += '\n';
		}

		if (this.sig0) {
			str += '\n';
			str += ';; SIG0 PSEUDOSECTION:\n';
			str += this.sig0.toString();
			str += '\n';
		}

		str += '\n';

		if (diff !== -1)
			str += `;; Query time: ${diff} msec\n`;

		if (host)
			str += `;; SERVER: ${host}#${port}(${host})\n`;

		if (sec !== -1)
			str += `;; WHEN: ${util.digDate(sec)}\n`;

		if (!this.size)
			this.size = this.getSize();

		if (this.size > 0)
			str += `;; MSG SIZE  rcvd: ${this.size}\n`;

		// Unbound style:
		if (this.trailing.length > 0) {
			str += '\n';
			str += ';; trailing garbage: 0x';
			str += this.trailing.toString('hex');
			str += '\n';
		}

		return str;
	}

	fromString(str) {
		let opcode = 0;
		let code = 0;
		let id = 0;
		let qdcount = 0;
		let ancount = 0;
		let nscount = 0;
		let arcount = 0;
		let enabled = false;
		let version = 0;
		let dnssec = false;
		let udp = MAX_UDP_SIZE;
		let options = null;
		let question = null;
		let answer = null;
		let authority = null;
		let additional = null;
		let tsig = null;
		let sig0 = null;
		let size = 0;
		let trailing = DUMMY;
		let index = -1;

		const lines = util.splitLines(str);

		const read = () => {
			index += 1;
			if (index === lines.length)
				throw new Error('Unexpected EOF.');
			return lines[index];
		};

		const expect = (prefix) => {
			const line = read();
			if (!util.startsWith(line, prefix))
				throw new Error('Unexpected line.');
			return line;
		};

		const seek = (prefix) => {
			for (; ;) {
				const line = read();
				if (util.startsWith(line, prefix))
					return line;
			}
		};

		const find = (prefix) => {
			const i = index;
			try {
				return seek(prefix);
			} catch (e) {
				index = i;
				return null;
			}
		};

		const peek = () => {
			if (index + 1 === lines.length)
				return '';
			const line = read();
			index -= 1;
			return line;
		};

		const hdrLine = seek(';; ->>HEADER<<-');
		const hdr = util.splitSP(hdrLine, 9);

		assert(hdr.length === 8);
		assert(hdr[0] === ';;');
		assert(hdr[1] === '->>HEADER<<-');
		assert(hdr[2] === 'opcode:');
		assert(util.endsWith(hdr[3], ','));
		assert(hdr[4] === 'status:');
		assert(util.endsWith(hdr[5], ','));
		assert(hdr[6] === 'id:');
		assert(!util.endsWith(hdr[7], ','));

		opcode = stringToOpcode(hdr[3].slice(0, -1));
		code = stringToCode(hdr[5].slice(0, -1));
		id = util.parseU16(hdr[7]);

		const subLine = expect(';; flags:');
		const sub = util.splitSP(subLine);

		assert(sub.length >= 9);
		assert(sub[0] === ';;');

		if (sub[1] === 'flags:;') {
			sub[1] = 'flags:';
			sub.splice(2, 0, ';');
		}

		assert(sub[1] === 'flags:');

		let bits = 0;
		let counts = null;

		for (let i = 2; i < sub.length; i++) {
			let flag = sub[i];

			const end = flag[flag.length - 1] === ';';

			if (end)
				flag = flag.slice(0, -1);

			switch (flag) {
				case '':
					break;
				case 'qr':
					bits |= Flag.QR;
					break;
				case 'aa':
					bits |= Flag.AA;
					break;
				case 'tc':
					bits |= Flag.TC;
					break;
				case 'rd':
					bits |= Flag.RD;
					break;
				case 'ra':
					bits |= Flag.RA;
					break;
				case 'z':
					bits |= Flag.Z;
					break;
				case 'ad':
					bits |= Flag.AD;
					break;
				case 'cd':
					bits |= Flag.CD;
					break;
				default:
					throw new Error(`Unknown flag: ${flag}.`);
			}

			if (end) {
				counts = sub.slice(i + 1);
				break;
			}
		}

		if (!counts)
			throw new Error('Malformed subheader.');

		assert(counts.length === 8);
		assert(counts[0] === 'QUERY:');
		assert(util.endsWith(counts[1], ','));
		assert(counts[2] === 'ANSWER:');
		assert(util.endsWith(counts[3], ','));
		assert(counts[4] === 'AUTHORITY:');
		assert(util.endsWith(counts[5], ','));
		assert(counts[6] === 'ADDITIONAL:');
		assert(!util.endsWith(counts[7], ','));

		qdcount = util.parseU16(counts[1].slice(0, -1));
		ancount = util.parseU16(counts[3].slice(0, -1));
		nscount = util.parseU16(counts[5].slice(0, -1));
		arcount = util.parseU16(counts[7]);
		options = [];

		if (find(';; OPT PSEUDOSECTION:')) {
			const line = expect('; EDNS: version: ');

			const hdr = util.splitSP(line);
			assert(hdr.length >= 7);
			assert(util.endsWith(hdr[3], ','));

			if (hdr[4] === 'flags:;') {
				hdr[4] = 'flags:';
				hdr.splice(5, 0, ';');
			}

			assert(hdr[4] === 'flags:');

			enabled = true;
			version = util.parseU8(hdr[3].slice(0, -1));

			assert(arcount > 0);
			arcount -= 1;

			let sub = null;

			for (let i = 5; i < hdr.length; i++) {
				let flag = hdr[i];

				const end = flag[flag.length - 1] === ';';

				if (end)
					flag = flag.slice(0, -1);

				switch (flag) {
					case '':
						break;
					case 'do':
						dnssec = true;
						break;
					default:
						throw new Error(`Unknown EDNS flag: ${flag}.`);
				}

				if (end) {
					sub = hdr.slice(i + 1);
					break;
				}
			}

			if (!sub)
				throw new Error('Malformed EDNS header.');

			assert(sub.length === 2);
			assert(sub[0] === 'udp:');

			udp = util.parseU16(sub[1]);

			while (util.startsWith(peek(), '; ')) {
				let line = read().substring(2);

				// Hack.
				if (util.startsWith(line, 'COOKIE: ')
					&& util.endsWith(line, ' (echoed)')) {
					line = line.slice(0, -9);
				}

				options.push(Option.fromString(line));
			}
		}

		question = [];

		if (qdcount > 0) {
			seek(';; QUESTION SECTION:');

			for (let i = 0; i < qdcount; i++) {
				const line = read();

				assert(line[0] === ';');

				const text = line.substring(1);
				const qs = Question.fromString(text);

				question.push(qs);
			}
		}

		answer = [];

		if (ancount > 0) {
			seek(';; ANSWER SECTION:');

			for (let i = 0; i < ancount; i++) {
				const line = read();
				const rr = Record.fromString(line);

				answer.push(rr);
			}
		}

		authority = [];

		if (nscount > 0) {
			seek(';; AUTHORITY SECTION:');

			for (let i = 0; i < nscount; i++) {
				const line = read();
				const rr = Record.fromString(line);

				authority.push(rr);
			}
		}

		additional = [];

		if (arcount > 0) {
			const section = seek(';; ');

			switch (section) {
				case ';; ADDITIONAL SECTION:':
				case ';; TSIG PSEUDOSECTION:':
				case ';; SIG0 PSEUDOSECTION:':
					break;
				default:
					throw new Error('Unexpected section.');
			}

			for (let i = 0; i < arcount; i++) {
				const line = read();

				if (line[0] === ';') {
					arcount += 1;
					continue;
				}

				const rr = Record.fromString<Record>(line);

				if (rr.isTSIG()) {
					tsig = rr;
					continue;
				}

				if (rr.isSIG0()) {
					sig0 = rr;
					continue;
				}

				additional.push(rr);
			}
		}

		const sizeLine = find(';; MSG SIZE  rcvd: ');

		if (sizeLine) {
			const text = sizeLine.substring(19);
			size = util.parseU32(text);
		}

		const garbageLine = find(';; trailing garbage: 0x');

		if (garbageLine) {
			const text = garbageLine.substring(23);
			trailing = util.parseHex(text);
		}

		this.opcode = opcode;
		this.code = code;
		this.id = id;
		this.flags = bits;

		this.edns.enabled = enabled;
		this.edns.version = version;
		this.edns.dnssec = dnssec;
		this.edns.size = udp;
		this.edns.code = code >>> 4;
		options = options;

		this.question = question;
		this.answer = answer;
		this.authority = authority;
		this.additional = additional;
		this.tsig = tsig;
		this.sig0 = sig0;

		this.size = size;
		this.malformed = false;
		this.trailing = trailing;

		return this;
	}

	getJSON() {
		if (!this.size)
			this.size = this.getSize();

		return {
			id: this.id,
			opcode: opcodeToString(this.opcode),
			code: codeToString(this.code),
			qr: this.qr,
			aa: this.aa,
			tc: this.tc,
			rd: this.rd,
			ra: this.ra,
			z: this.z,
			ad: this.ad,
			cd: this.cd,
			question: this.question.map(qs => qs.toJSON()),
			answer: this.answer.map(rr => rr.toJSON()),
			authority: this.authority.map(rr => rr.toJSON()),
			additional: this.additional.map(rr => rr.toJSON()),
			edns: this.edns.enabled ? this.edns.toJSON() : undefined,
			tsig: this.tsig ? this.tsig.data.toJSON() : undefined,
			sig0: this.sig0 ? this.sig0.data.toJSON() : undefined,
			size: this.size,
			trailing: this.trailing.length > 0
				? this.trailing.toString('hex')
				: undefined
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert((json.id & 0xffff) === json.id);
		assert(typeof json.qr === 'boolean');
		assert(typeof json.aa === 'boolean');
		assert(typeof json.tc === 'boolean');
		assert(typeof json.rd === 'boolean');
		assert(typeof json.ra === 'boolean');
		assert(typeof json.z === 'boolean');
		assert(typeof json.ad === 'boolean');
		assert(typeof json.cd === 'boolean');
		assert(Array.isArray(json.question));
		assert(Array.isArray(json.answer));
		assert(Array.isArray(json.authority));
		assert(Array.isArray(json.additional));

		this.id = json.id;
		this.opcode = stringToOpcode(json.opcode);
		this.code = stringToCode(json.code);
		this.qr = json.qr;
		this.aa = json.aa;
		this.tc = json.tc;
		this.rd = json.rd;
		this.ra = json.ra;
		this.z = json.z;
		this.ad = json.ad;
		this.cd = json.cd;

		for (const qs of json.question)
			this.question.push(Question.fromJSON(qs));

		for (const rr of json.answer)
			this.answer.push(Record.fromJSON(rr));

		for (const rr of json.authority)
			this.authority.push(Record.fromJSON(rr));

		for (const rr of json.additional) {
			const record = Record.fromJSON<Record>(rr);

			assert(!record.isOPT());
			assert(!record.isTSIG());
			assert(!record.isSIG0());

			this.additional.push(record);
		}

		if (json.edns != null) {
			this.edns.fromJSON(json.edns);
			this.code &= 0x0f;
			this.code |= this.edns.code << 4;
		}

		if (json.tsig != null) {
			this.tsig = new Record();
			this.tsig.name = '.';
			this.tsig.type = RecordType.TSIG;
			this.tsig.class = QuestionClass.ANY;
			this.tsig.ttl = 0;
			this.tsig.data = TSIGRecord.fromJSON(json.tsig);
		}

		if (json.sig0 != null) {
			this.sig0 = new Record();
			this.sig0.name = '.';
			this.sig0.type = RecordType.SIG;
			this.sig0.class = QuestionClass.ANY;
			this.sig0.ttl = 0;
			this.sig0.data = SIGRecord.fromJSON(json.sig0);
		}

		if (json.size != null) {
			assert((json.size >>> 0) === json.size);
			this.size = json.size;
		}

		this.malformed = false;

		if (json.trailing != null)
			this.trailing = util.parseHex(json.trailing);

		return this;
	}
}

/**
 * EDNS
 */

class EDNS extends Struct {
	enabled: boolean;
	size: number;
	code: number;
	version: number;
	flags: number;
	options: any[];

	constructor() {
		super();

		this.enabled = false;
		this.size = MAX_UDP_SIZE;
		this.code = 0;
		this.version = 0;
		this.flags = 0;
		this.options = [];
	}

	inject(edns: EDNS) {
		// assert(edns instanceof this.constructor);
		this.enabled = edns.enabled;
		this.size = edns.size;
		this.code = edns.code;
		this.version = edns.version;
		this.flags = edns.flags;
		this.options = edns.options.slice();
		return this;
	}

	clone() {
		const copy = new EDNS();
		return copy.inject(this);
	}

	reset() {
		this.enabled = false;
		this.size = MAX_UDP_SIZE;
		this.code = 0;
		this.version = 0;
		this.flags = 0;
		this.options = [];
		return this;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		for (const opt of this.options)
			opt.canonical();
		return this;
	}

	getFlag(bit) {
		return (this.flags & bit) !== 0;
	}

	setFlag(bit, value) {
		if (value)
			this.flags |= bit;
		else
			this.flags &= ~bit;

		return Boolean(value);
	}

	get dnssec() {
		return this.getFlag(EFlag.DO);
	}

	set dnssec(value) {
		this.setFlag(EFlag.DO, value);
	}

	set(code, option) {
		assert((code & 0xffff) === code);
		assert(option instanceof OptionData);

		const opt = new Option();
		opt.code = code;
		opt.option = option;

		for (let i = 0; i < this.options.length; i++) {
			const item = this.options[i];
			if (item.code === code) {
				this.options[i] = opt;
				return this;
			}
		}

		this.options.push(opt);

		return this;
	}

	get(code) {
		assert((code & 0xffff) === code);

		for (const opt of this.options) {
			if (opt.code === code)
				return opt.option;
		}

		return null;
	}

	has(code) {
		return this.get(code) != null;
	}

	remove(code) {
		assert((code & 0xffff) === code);

		for (let i = 0; i < this.options.length; i++) {
			const opt = this.options[i];
			if (opt.code === code) {
				this.options.splice(i, 1);
				return opt.option;
			}
		}

		return null;
	}

	add(option) {
		assert(option instanceof OptionData);
		assert(option.code !== EOption.RESERVED);
		return this.set(option.code, option);
	}

	setCookie(cookie) {
		assert(Buffer.isBuffer(cookie));
		const option = new COOKIEOption();
		option.cookie = cookie;
		return this.add(option);
	}

	getCookie() {
		const opt = this.get(EOption.COOKIE);

		if (!opt)
			return null;

		return opt.cookie;
	}

	hasCookie() {
		return this.getCookie() != null;
	}

	removeCookie() {
		const opt = this.remove(EOption.COOKIE);

		if (!opt)
			return null;

		return opt.cookie;
	}

	getDataSize(map) {
		let size = 0;
		for (const opt of this.options)
			size += opt.getSize(map);
		return size;
	}

	getSize(map) {
		let size = 0;
		size += 1;
		size += 10;
		size += this.getDataSize(map);
		return size;
	}

	write(bw, map) {
		bw.writeU8(0);
		bw.writeU16BE(RecordType.OPT);
		bw.writeU16BE(this.size);

		bw.writeU8(this.code);
		bw.writeU8(this.version);
		bw.writeU16BE(this.flags);

		bw.writeU16BE(0);

		const off = bw.offset;

		for (const opt of this.options)
			opt.write(bw, map);

		const size = bw.offset - off;

		bw.data.writeUInt16BE(size, off - 2, true);

		return this;
	}

	read(br) {
		assert(br.readU8() === 0);
		assert(br.readU16BE() === RecordType.OPT);

		this.size = br.readU16BE();

		this.code = br.readU8();
		this.version = br.readU8();
		this.flags = br.readU16BE();

		const size = br.readU16BE();
		const {data, offset} = br;
		const len = offset + size;

		assert(len <= data.length);

		const cdata = data.slice(0, len);
		const cbr = bio.read(cdata);
		cbr.offset = offset;

		while (cbr.left())
			this.options.push(Option.read(cbr));

		br.offset = cbr.offset;

		return this;
	}

	setRecord(rr) {
		assert(rr instanceof Record);
		assert(rr.type === RecordType.OPT);

		const rd = rr.data;

		this.enabled = true;
		this.size = rr.class;
		this.code = (rr.ttl >>> 24) & 0xff;
		this.version = (rr.ttl >>> 16) & 0xff;
		this.flags = rr.ttl & 0xffff;
		this.options = [];

		for (const opt of rd.options)
			this.options.push(opt);

		return this;
	}

	toRecord() {
		const rr = new Record();
		const rd = new OPTRecord();

		rr.name = '.';
		rr.type = RecordType.OPT;

		rr.class = this.size;

		rr.ttl |= (this.code & 0xff) << 24;
		rr.ttl |= (this.version & 0xff) << 16;
		rr.ttl |= this.flags & 0xffff;
		rr.ttl >>>= 0;

		rr.data = rd;

		for (const opt of this.options)
			rd.options.push(opt);

		return rr;
	}

	fromRecord(rr) {
		return this.setRecord(rr);
	}

	static fromRecord(rr) {
		return new this().fromRecord(rr);
	}

	getJSON() {
		return {
			enabled: this.enabled,
			size: this.size,
			code: this.code,
			version: this.version,
			dnssec: this.dnssec,
			options: this.options.map(opt => opt.toJSON())
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert(typeof json.enabled === 'boolean');
		assert((json.size & 0xffff) === json.size);
		assert((json.code & 0xff) === json.code);
		assert((json.version & 0xff) === json.version);
		assert(typeof json.dnssec === 'boolean');
		assert(Array.isArray(json.options));

		this.enabled = json.enabled;
		this.size = json.size;
		this.code = json.code;
		this.version = json.version;
		this.dnssec = json.dnssec;

		for (const opt of json.options)
			this.options.push(Option.fromJSON(opt));

		return this;
	}
}

/**
 * Question
 */

class Question extends Struct {
	name: string;
	type: RecordType;
	class: QuestionClass;

	constructor(name?: string, type?: RecordType | string) {
		super();

		if (name == null)
			name = '';

		if (type == null)
			type = RecordType.ANY;

		if (typeof type === 'string')
			type = stringToType(type);

		// assert(typeof name === 'string');
		assert((type & 0xffff) === type);

		this.name = util.fqdn(name);
		this.type = type;
		this.class = QuestionClass.IN;
	}

	equals(qs) {
		assert(qs instanceof Question);
		return util.equal(this.name, qs.name)
			&& this.type === qs.type
			&& this.class === qs.class;
	}

	inject(qs) {
		assert(qs instanceof this.constructor);
		this.name = qs.name;
		this.type = qs.type;
		this.class = qs.class;
		return this;
	}

	clone() {
		const qs = new Question();
		return qs.inject(this);
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.name = this.name.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.name, map) + 4;
	}

	write(bw, map) {
		writeNameBW(bw, this.name, map);
		bw.writeU16BE(this.type);
		bw.writeU16BE(this.class);
		return this;
	}

	read(br) {
		this.name = readNameBR(br);

		if (br.left() === 0)
			return this;

		this.type = br.readU16BE();

		if (br.left() === 0)
			return this;

		this.class = br.readU16BE();

		return this;
	}

	toString() {
		const name = this.name;
		const class_ = classToString(this.class);
		const type = typeToString(this.type);
		return `${name} ${class_} ${type}`;
	}

	fromString(str) {
		const parts = util.splitSP(str, 4);

		assert(parts.length === 3);
		assert(encoding.isName(parts[0]));

		this.name = parts[0];
		this.class = stringToClass(parts[1]);
		this.type = stringToType(parts[2]);

		return this;
	}

	getJSON() {
		return {
			name: this.name,
			class: classToString(this.class),
			type: typeToString(this.type)
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert(typeof json.name === 'string');
		assert(encoding.isName(json.name));

		this.name = json.name;
		this.class = stringToClass(json.class);
		this.type = stringToType(json.type);

		return this;
	}
}

/**
 * Record
 */

class Record<T extends RecordData = RecordData> extends Struct {
	name: string;
	type: RecordType;
	class: QuestionClass;
	ttl: number;
	data: T;

	constructor() {
		super();
		this.name = '.';
		this.type = RecordType.UNKNOWN;
		this.class = QuestionClass.IN;
		this.ttl = 0;
		this.data = new UNKNOWNRecord() as any;
	}

	inject(rr) {
		assert(rr instanceof this.constructor);
		this.name = rr.name;
		this.type = rr.type;
		this.class = rr.class;
		this.ttl = rr.ttl;
		this.data = rr.data;
		return this;
	}

	deepClone() {
		const rr = new Record();
		return rr.decode(this.encode());
	}

	canonical() {
		this.name = this.name.toLowerCase();
		this.data.canonical();
		return this;
	}

	isOPT() {
		return this.type === RecordType.OPT;
	}

	isTSIG() {
		return this.name === '.'
			&& this.type === RecordType.TSIG
			&& this.class === QuestionClass.ANY
			&& this.ttl === 0;
	}

	isSIG0() {
		return this.name === '.'
			&& this.type === RecordType.SIG
			&& this.class === QuestionClass.ANY
			&& this.ttl === 0
			&& this.data.typeCovered === 0;
	}

	getSize(map?) {
		let size = 0;
		size += sizeName(this.name, map);
		size += 10;
		size += this.data.getSize(map);
		return size;
	}

	write(bw, map?) {
		writeNameBW(bw, this.name, map);
		bw.writeU16BE(this.type);
		bw.writeU16BE(this.class);
		bw.writeU32BE(this.ttl);
		bw.writeU16BE(0);

		const off = bw.offset;

		this.data.write(bw, map);

		const size = bw.offset - off;

		bw.data.writeUInt16BE(size, off - 2, true);

		return this;
	}

	read(br) {
		this.name = readNameBR(br);
		this.type = br.readU16BE();
		this.class = br.readU16BE();
		this.ttl = br.readU32BE();

		const size = br.readU16BE();
		const child = br.readChild(size);

		this.data = readData(this.type, child) as any;

		return this;
	}

	toString() {
		const name = this.name;
		const ttl = this.ttl.toString(10);
		const class_ = classToString(this.class);
		const type = typeToString(this.type);
		const isUnknown = RecordType[this.type] == null;

		let body = this.data.toString();

		if (isUnknown) {
			assert(this.data.type === RecordType.UNKNOWN);
			const size = this.data.getSize().toString(10);
			body = `\\# ${size} ${body}`;
		}

		return `${name} ${ttl} ${class_} ${type} ${body}`;
	}

	fromString(str) {
		const scan = lazy(require, './scan');
		const rr = scan.parseRecord(exports, str);
		return this.inject(rr);
	}

	getJSON() {
		return {
			name: this.name,
			ttl: this.ttl,
			class: classToString(this.class),
			type: typeToString(this.type),
			data: this.data.toJSON()
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert(typeof json.name === 'string');
		assert(encoding.isName(json.name));
		assert((json.ttl >>> 0) === json.ttl);
		assert(json.data && typeof json.data === 'object');

		this.name = json.name;
		this.ttl = json.ttl;
		this.class = stringToClass(json.class);
		this.type = stringToType(json.type);

		const RD = recordsByVal[this.type];

		let data;
		if (RecordType[json.type] == null) {
			const rd = util.parseHex(json.data.data);

			if (RD)
				data = RD.decode(rd);
			else
				data = UNKNOWNRecord.decode(rd);
		} else {
			if (!RD)
				throw new Error(`Unknown record type: ${json.type}.`);

			data = RD.fromJSON(json.data);
		}

		this.data = data;

		return this;
	}
}

/**
 * RecordData
 */

class RecordData extends Struct {
	typeCovered: number;

	constructor() {
		super();
	}

	get type() {
		return RecordType.UNKNOWN;
	}

	_schema() {
		const schema = lazy(require, './schema');
		const s = schema.records[this.type];

		if (!s)
			return schema.records[RecordType.UNKNOWN];

		return s;
	}

	canonical() {
		return this;
	}

	toString() {
		const schema = lazy(require, './schema');
		return schema.toString(exports, this, this._schema());
	}

	fromString(str) {
		const scan = lazy(require, './scan');
		const rd = scan.parseData(exports, str);
		return this.inject(rd);
	}

	getJSON() {
		const schema = lazy(require, './schema');
		return schema.toJSON(exports, this, this._schema());
	}

	fromJSON(json) {
		const schema = lazy(require, './schema');
		return schema.fromJSON(exports, this, this._schema(), json);
	}
}

/**
 * UNKNOWN Record
 */

class UNKNOWNRecord extends RecordData {
	data: Buffer;

	constructor() {
		super();
		this.data = DUMMY;
	}

	get type() {
		return RecordType.UNKNOWN;
	}

	getSize() {
		return this.data.length;
	}

	write(bw) {
		bw.writeBytes(this.data);
		return this;
	}

	read(br) {
		this.data = br.readBytes(br.left());
		return this;
	}
}

/**
 * A Record
 * Address Record
 * @see https://tools.ietf.org/html/rfc1035
 */

class ARecord extends RecordData {
	address: string;

	constructor() {
		super();
		this.address = '0.0.0.0';
	}

	get type() {
		return RecordType.A;
	}

	getSize() {
		return 4;
	}

	write(bw) {
		writeIP(bw, this.address, 4);
		return this;
	}

	read(br) {
		this.address = readIP(br, 4);
		return this;
	}
}

/**
 * NS Record
 * Name Server Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class NSRecord extends RecordData {
	ns: string;

	constructor() {
		super();
		this.ns = '.';
	}

	get type() {
		return RecordType.NS;
	}

	canonical() {
		this.ns = this.ns.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.ns, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.ns, map);
		return this;
	}

	read(br) {
		this.ns = readNameBR(br);
		return this;
	}
}

/**
 * MD Record
 * Mail Destination Record (obsolete)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc973
 */

class MDRecord extends RecordData {
	md: string;

	constructor() {
		super();
		this.md = '.';
	}

	get type() {
		return RecordType.MD;
	}

	canonical() {
		this.md = this.md.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.md, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.md, map);
		return this;
	}

	read(br) {
		this.md = readNameBR(br);
		return this;
	}
}

/**
 * MF Record
 * Mail Forwarder Record (obsolete)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc973
 */

class MFRecord extends RecordData {
	mf: string;

	constructor() {
		super();
		this.mf = '.';
	}

	get type() {
		return RecordType.MF;
	}

	canonical() {
		this.mf = this.mf.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.mf, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.mf, map);
		return this;
	}

	read(br) {
		this.mf = readNameBR(br);
		return this;
	}
}

/**
 * CNAME Record
 * Canonical Name Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class CNAMERecord extends RecordData {
	target: string;

	constructor() {
		super();
		this.target = '.';
	}

	get type() {
		return RecordType.CNAME;
	}

	canonical() {
		this.target = this.target.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.target, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.target, map);
		return this;
	}

	read(br) {
		this.target = readNameBR(br);
		return this;
	}
}

/**
 * SOA Record
 * Start of Authority Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 * @see https://tools.ietf.org/html/rfc2308
 */

class SOARecord extends RecordData {
	ns: string;
	mbox: string;
	serial: number;
	refresh: number;
	retry: number;
	expire: number;
	minttl: number;

	constructor() {
		super();
		this.ns = '.';
		this.mbox = '.';
		this.serial = 0;
		this.refresh = 0;
		this.retry = 0;
		this.expire = 0;
		this.minttl = 0;
	}

	get type() {
		return RecordType.SOA;
	}

	canonical() {
		this.ns = this.ns.toLowerCase();
		this.mbox = this.mbox.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.ns, map);
		size += sizeName(this.mbox, map);
		size += 20;
		return size;
	}

	write(bw, map?) {
		writeNameBW(bw, this.ns, map);
		writeNameBW(bw, this.mbox, map);
		bw.writeU32BE(this.serial);
		bw.writeU32BE(this.refresh);
		bw.writeU32BE(this.retry);
		bw.writeU32BE(this.expire);
		bw.writeU32BE(this.minttl);
		return this;
	}

	read(br) {
		this.ns = readNameBR(br);
		this.mbox = readNameBR(br);
		this.serial = br.readU32BE();
		this.refresh = br.readU32BE();
		this.retry = br.readU32BE();
		this.expire = br.readU32BE();
		this.minttl = br.readU32BE();
		return this;
	}
}

/**
 * MB Record
 * Mailbox Record (expiremental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MBRecord extends RecordData {
	mb: string;

	constructor() {
		super();
		this.mb = '.';
	}

	get type() {
		return RecordType.MB;
	}

	canonical() {
		this.mb = this.mb.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.mb, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.mb, map);
		return this;
	}

	read(br) {
		this.mb = readNameBR(br);
		return this;
	}
}

/**
 * MG Record
 * Mail Group Record (experimental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MGRecord extends RecordData {
	mg: string;

	constructor() {
		super();
		this.mg = '.';
	}

	get type() {
		return RecordType.MG;
	}

	canonical() {
		this.mg = this.mg.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.mg, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.mg, map);
		return this;
	}

	read(br) {
		this.mg = readNameBR(br);
		return this;
	}
}

/**
 * MR Record
 * Mail Rename Record (experimental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MRRecord extends RecordData {
	mr: string;

	constructor() {
		super();
		this.mr = '.';
	}

	get type() {
		return RecordType.MR;
	}

	canonical() {
		this.mr = this.mr.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.mr, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.mr, map);
		return this;
	}

	read(br) {
		this.mr = readNameBR(br);
		return this;
	}
}

/**
 * NULL Record
 * Null Record (obsolete)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 */

class NULLRecord extends UNKNOWNRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.NULL;
	}
}

/**
 * WKS Record
 * Well-known Services Record (deprecated)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc1123
 * @see https://tools.ietf.org/html/rfc1127
 */

class WKSRecord extends RecordData {
	address: string;
	protocol: number;
	bitmap: Buffer;

	constructor() {
		super();
		this.address = '0.0.0.0';
		this.protocol = 0;
		this.bitmap = DUMMY;
	}

	get type() {
		return RecordType.WKS;
	}

	setPorts(ports) {
		this.bitmap = encoding.toPortmap(ports);
		return this;
	}

	getPorts() {
		return encoding.fromPortmap(this.bitmap);
	}

	hasPort(port) {
		return encoding.hasPort(this.bitmap, port);
	}

	getSize() {
		return 5 + this.bitmap.length;
	}

	write(bw) {
		writeIP(bw, this.address, 4);
		bw.writeU8(this.protocol);
		bw.writeBytes(this.bitmap);
		return this;
	}

	read(br) {
		this.address = readIP(br, 4);
		this.protocol = br.readU8();
		this.bitmap = br.readBytes(br.left());
		return this;
	}
}

/**
 * PTR Record
 * Pointer Record
 * @see https://tools.ietf.org/html/rfc1035
 */

class PTRRecord extends RecordData {
	ptr: string;

	constructor() {
		super();
		this.ptr = '.';
	}

	get type() {
		return RecordType.PTR;
	}

	canonical() {
		this.ptr = this.ptr.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.ptr, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.ptr, map);
		return this;
	}

	read(br) {
		this.ptr = readNameBR(br);
		return this;
	}
}

/**
 * HINFO Record
 * Host Information Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc883
 */

class HINFORecord extends RecordData {
	cpu: string;
	os: string;

	constructor() {
		super();
		this.cpu = '';
		this.os = '';
	}

	get type() {
		return RecordType.HINFO;
	}

	getSize() {
		let size = 0;
		size += sizeString(this.cpu);
		size += sizeString(this.os);
		return size;
	}

	write(bw) {
		writeStringBW(bw, this.cpu);
		writeStringBW(bw, this.os);
		return this;
	}

	read(br) {
		this.cpu = readStringBR(br);
		this.os = readStringBR(br);
		return this;
	}
}

/**
 * MINFO Record
 * Mail Info Record (experimental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MINFORecord extends RecordData {
	rmail: string;
	email: string;

	constructor() {
		super();
		this.rmail = '.';
		this.email = '.';
	}

	get type() {
		return RecordType.MINFO;
	}

	canonical() {
		this.rmail = this.rmail.toLowerCase();
		this.email = this.email.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.rmail, map);
		size += sizeName(this.email, map);
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.rmail, map);
		writeNameBW(bw, this.email, map);
		return this;
	}

	read(br) {
		this.rmail = readNameBR(br);
		this.email = readNameBR(br);
		return this;
	}
}

/**
 * MX Record
 * Mail Exchange Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 * @see https://tools.ietf.org/html/rfc7505
 */

class MXRecord extends RecordData {
	preference: number;
	mx: string;

	constructor() {
		super();
		this.preference = 0;
		this.mx = '.';
	}

	get type() {
		return RecordType.MX;
	}

	canonical() {
		this.mx = this.mx.toLowerCase();
		return this;
	}

	getSize(map) {
		return 2 + sizeName(this.mx, map);
	}

	write(bw, map) {
		bw.writeU16BE(this.preference);
		writeNameBW(bw, this.mx, map);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.mx = readNameBR(br);
		return this;
	}
}

/**
 * TXT Record
 * Text Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class TXTRecord extends RecordData {
	private txt: string[];

	constructor() {
		super();
		this.txt = [];
	}

	get type() {
		return RecordType.TXT;
	}

	getSize() {
		let size = 0;
		for (const txt of this.txt)
			size += sizeString(txt);
		return size;
	}

	write(bw) {
		for (const txt of this.txt)
			writeStringBW(bw, txt);
		return this;
	}

	read(br) {
		while (br.left())
			this.txt.push(readStringBR(br));
		return this;
	}
}

/**
 * RP Record
 * Responsible Person Record
 * @see https://tools.ietf.org/html/rfc1183
 */

class RPRecord extends RecordData {
	mbox: string;
	txt: string;

	constructor() {
		super();
		this.mbox = '.';
		this.txt = '.';
	}

	get type() {
		return RecordType.RP;
	}

	canonical() {
		this.mbox = this.mbox.toLowerCase();
		this.txt = this.txt.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.mbox, map);
		size += sizeName(this.txt, map);
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.mbox, map);
		writeNameBW(bw, this.txt, map);
		return this;
	}

	read(br) {
		this.mbox = readNameBR(br);
		this.txt = readNameBR(br);
		return this;
	}
}

/**
 * AFSDB Record
 * AFS Database Record
 * @see https://tools.ietf.org/html/rfc1183
 */

class AFSDBRecord extends RecordData {
	subtype: number;
	hostname: string;

	constructor() {
		super();
		this.subtype = 0;
		this.hostname = '.';
	}

	get type() {
		return RecordType.AFSDB;
	}

	canonical() {
		this.hostname = this.hostname.toLowerCase();
		return this;
	}

	getSize(map) {
		return 2 + sizeName(this.hostname, map);
	}

	write(bw, map) {
		bw.writeU16BE(this.subtype);
		writeNameBW(bw, this.hostname, map);
		return this;
	}

	read(br) {
		this.subtype = br.readU16BE();
		this.hostname = readNameBR(br);
		return this;
	}
}

/**
 * X25Record
 * X25 Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1183
 */

class X25Record extends RecordData {
	psdnAddress: string;

	constructor() {
		super();
		this.psdnAddress = '';
	}

	get type() {
		return RecordType.X25;
	}

	getSize() {
		return sizeString(this.psdnAddress);
	}

	write(bw) {
		writeStringBW(bw, this.psdnAddress);
		return this;
	}

	read(br) {
		this.psdnAddress = readStringBR(br, true);
		return this;
	}
}

/**
 * ISDN Record
 * ISDN Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1183
 */

class ISDNRecord extends RecordData {
	address: string;
	sa: string;

	constructor() {
		super();
		this.address = '';
		this.sa = '';
	}

	get type() {
		return RecordType.ISDN;
	}

	getSize() {
		let size = 0;
		size += sizeString(this.address);
		size += sizeString(this.sa);
		return size;
	}

	write(bw) {
		writeStringBW(bw, this.address);
		writeStringBW(bw, this.sa);
		return this;
	}

	read(br) {
		this.address = readStringBR(br, true);
		this.sa = readStringBR(br, true);
		return this;
	}
}

/**
 * RT Record
 * RT Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1183
 */

class RTRecord extends RecordData {
	preference: number;
	host: string;

	constructor() {
		super();
		this.preference = 0;
		this.host = '.';
	}

	get type() {
		return RecordType.RT;
	}

	canonical() {
		this.host = this.host.toLowerCase();
		return this;
	}

	getSize(map) {
		return 2 + sizeName(this.host, map);
	}

	write(bw, map) {
		bw.writeU16BE(this.preference);
		writeNameBW(bw, this.host, map);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.host = readNameBR(br);
		return this;
	}
}

/**
 * NSAP Record
 * Network Service Access Point Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1706
 */

class NSAPRecord extends RecordData {
	nsap: Buffer;

	constructor() {
		super();
		this.nsap = DUMMY;
	}

	get type() {
		return RecordType.NSAP;
	}

	getSize() {
		return this.nsap.length;
	}

	write(bw) {
		bw.writeBytes(this.nsap);
		return this;
	}

	read(br) {
		this.nsap = br.readBytes(br.left());
		return this;
	}
}

/**
 * NSAPPTR Record
 * Network Service Access Point PTR Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1348
 */

class NSAPPTRRecord extends PTRRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.NSAPPTR;
	}
}

/**
 * SIG Record
 * Signature Record (obsolete)
 * @see https://tools.ietf.org/html/rfc2065
 * @see https://tools.ietf.org/html/rfc3755
 */

class SIGRecord extends RecordData {
	algorithm: number;
	labels: number;
	origTTL: number;
	expiration: number;
	inception: number;
	keyTag: number;
	signerName: string;
	signature: Buffer;

	constructor() {
		super();
		this.typeCovered = 0;
		this.algorithm = 0;
		this.labels = 0;
		this.origTTL = 0;
		this.expiration = 0;
		this.inception = 0;
		this.keyTag = 0;
		this.signerName = '.';
		this.signature = DUMMY;
	}

	get type() {
		return RecordType.SIG;
	}

	canonical() {
		this.signerName = this.signerName.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += 18;
		size += sizeName(this.signerName, map);
		size += this.signature.length;
		return size;
	}

	write(bw, map) {
		bw.writeU16BE(this.typeCovered);
		bw.writeU8(this.algorithm);
		bw.writeU8(this.labels);
		bw.writeU32BE(this.origTTL);
		bw.writeU32BE(this.expiration);
		bw.writeU32BE(this.inception);
		bw.writeU16BE(this.keyTag);
		writeNameBW(bw, this.signerName, map);
		bw.writeBytes(this.signature);
		return this;
	}

	read(br) {
		this.typeCovered = br.readU16BE();
		this.algorithm = br.readU8();
		this.labels = br.readU8();
		this.origTTL = br.readU32BE();
		this.expiration = br.readU32BE();
		this.inception = br.readU32BE();
		this.keyTag = br.readU16BE();
		this.signerName = readNameBR(br);
		this.signature = br.readBytes(br.left());
		return this;
	}

	toTBS() {
		const signerName = this.signerName;
		const signature = this.signature;

		this.signerName = signerName.toLowerCase();
		this.signature = DUMMY;

		let raw = null;

		try {
			raw = this.encode();
		} finally {
			this.signerName = signerName;
			this.signature = signature;
		}

		return raw;
	}

	validityPeriod(t) {
		if (t == null)
			t = util.now();

		return t >= this.inception && t <= this.expiration;
	}

	getJSON() {
		const json = super.getJSON();
		json.algName = algToString(this.algorithm);
		return json;
	}

	toString() {
		const algName = algToString(this.algorithm);

		let str = super.toString();

		// Mimic `delv`.
		str += ' ';
		str += ` ; alg = ${algName}`;

		return str;
	}
}

/**
 * KEY Record
 * Key Record (obsolete)
 * @see https://tools.ietf.org/html/rfc2065
 * @see https://tools.ietf.org/html/rfc3755
 */

class KEYRecord extends RecordData {
	flags: number;
	protocol: number;
	algorithm: number;
	publicKey: Buffer;

	constructor() {
		super();
		this.flags = 0;
		this.protocol = 0;
		this.algorithm = 0;
		this.publicKey = DUMMY;
	}

	get type() {
		return RecordType.KEY;
	}

	getSize() {
		return 4 + this.publicKey.length;
	}

	write(bw) {
		bw.writeU16BE(this.flags);
		bw.writeU8(this.protocol);
		bw.writeU8(this.algorithm);
		bw.writeBytes(this.publicKey);
		return this;
	}

	read(br) {
		this.flags = br.readU16BE();
		this.protocol = br.readU8();
		this.algorithm = br.readU8();
		this.publicKey = br.readBytes(br.left());
		return this;
	}

	keyTag(raw?) {
		if (this.algorithm === 0 /* RSAMD5 */) {
			const key = this.publicKey;

			if (key.length < 2)
				return 0;

			return key.readUInt16BE(key.length - 2, true);
		}

		if (!raw)
			raw = this.encode();

		let tag = 0;

		for (let i = 0; i < raw.length; i++) {
			const ch = raw[i];

			if (i & 1)
				tag += ch;
			else
				tag += ch << 8;

			tag |= 0;
		}

		tag += (tag >>> 16) & 0xffff;
		tag &= 0xffff;

		return tag;
	}

	getJSON() {
		let type = 'ZSK';

		if (this.flags & KeyFlag.SEP)
			type = 'KSK';

		const json = super.getJSON();

		json.keyType = type;
		json.keyTag = this.keyTag();
		json.algName = algToString(this.algorithm);

		return json;
	}

	toString() {
		let type = 'ZSK';

		if (this.flags & KeyFlag.SEP)
			type = 'KSK';

		const algName = algToString(this.algorithm);
		const keyTag = this.keyTag();

		let str = super.toString();

		// Mimic `delv`.
		str += ' ';
		str += ` ; ${type}`;
		str += ` ; alg = ${algName}`;
		str += ` ; key id = ${keyTag}`;

		return str;
	}
}

/**
 * PX Record
 * Pointer to X400 Mapping Information Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc2163
 */

class PXRecord extends RecordData {
	preference: number;
	map822: string;
	mapx400: string;

	constructor() {
		super();
		this.preference = 0;
		this.map822 = '.';
		this.mapx400 = '.';
	}

	get type() {
		return RecordType.PX;
	}

	canonical() {
		this.map822 = this.map822.toLowerCase();
		this.mapx400 = this.mapx400.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += 2;
		size += sizeName(this.map822, map);
		size += sizeName(this.mapx400, map);
		return size;
	}

	write(bw, map) {
		bw.writeU16BE(this.preference);
		writeNameBW(bw, this.map822, map);
		writeNameBW(bw, this.mapx400, map);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.map822 = readNameBR(br);
		this.mapx400 = readNameBR(br);
		return this;
	}
}

/**
 * GPOS Record
 * Geographical Position Record (deprecated)
 * @see https://tools.ietf.org/html/rfc1712
 */

class GPOSRecord extends RecordData {
	longitude: string;
	latitude: string;
	altitude: string;

	constructor() {
		super();
		this.longitude = '';
		this.latitude = '';
		this.altitude = '';
	}

	get type() {
		return RecordType.GPOS;
	}

	getSize() {
		let size = 0;
		size += sizeString(this.longitude);
		size += sizeString(this.latitude);
		size += sizeString(this.altitude);
		return size;
	}

	write(bw) {
		writeStringBW(bw, this.longitude);
		writeStringBW(bw, this.latitude);
		writeStringBW(bw, this.altitude);
		return this;
	}

	read(br) {
		this.longitude = readStringBR(br, true);
		this.latitude = readStringBR(br, true);
		this.altitude = readStringBR(br, true);
		return this;
	}
}

/**
 * AAAA Record
 * IPv6 Address Record
 * @see https://tools.ietf.org/html/rfc3596
 */

class AAAARecord extends RecordData {
	address: string;

	constructor() {
		super();
		this.address = '::';
	}

	get type() {
		return RecordType.AAAA;
	}

	getSize() {
		return 16;
	}

	write(bw) {
		writeIP(bw, this.address, 16);
		return this;
	}

	read(br) {
		this.address = readIP(br, 16);
		return this;
	}
}

/**
 * LOC Record
 * Location Record
 * @see https://tools.ietf.org/html/rfc1876
 */

class LOCRecord extends RecordData {
	version: number;
	size: number;
	horizPre: number;
	vertPre: number;
	latitude: number;
	longitude: number;
	altitude: number;

	constructor() {
		super();
		this.version = 0;
		this.size = 0;
		this.horizPre = 0;
		this.vertPre = 0;
		this.latitude = 0;
		this.longitude = 0;
		this.altitude = 0;
	}

	get type() {
		return RecordType.LOC;
	}

	getSize() {
		return 16;
	}

	write(bw) {
		bw.writeU8(this.version);
		bw.writeU8(this.size);
		bw.writeU8(this.horizPre);
		bw.writeU8(this.vertPre);
		bw.writeU32BE(this.latitude);
		bw.writeU32BE(this.longitude);
		bw.writeU32BE(this.altitude);
		return this;
	}

	read(br) {
		this.version = br.readU8();
		this.size = br.readU8();
		this.horizPre = br.readU8();
		this.vertPre = br.readU8();
		this.latitude = br.readU32BE();
		this.longitude = br.readU32BE();
		this.altitude = br.readU32BE();
		return this;
	}
}

/**
 * NXT Record
 * Next Domain Record (obsolete)
 * @see https://tools.ietf.org/html/rfc2065#section-5.2
 * @see https://tools.ietf.org/html/rfc2535#section-5.1
 * @see https://tools.ietf.org/html/rfc3755
 */

class NXTRecord extends RecordData {
	nextDomain: string;
	typeBitmap: Buffer;

	constructor() {
		super();
		this.nextDomain = '.';
		this.typeBitmap = DUMMY;
	}

	get type() {
		return RecordType.NXT;
	}

	canonical() {
		this.nextDomain = this.nextDomain.toLowerCase();
		return this;
	}

	setTypes(types) {
		this.typeBitmap = toBitmap(types);
		return this;
	}

	getTypes() {
		return fromBitmap(this.typeBitmap);
	}

	hasType(type) {
		return hasType(this.typeBitmap, type);
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.nextDomain, map);
		size += this.typeBitmap.length;
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.nextDomain, map);
		bw.writeBytes(this.typeBitmap);
		return this;
	}

	read(br) {
		this.nextDomain = readNameBR(br);
		this.typeBitmap = br.readBytes(br.left());
		return this;
	}
}

/**
 * EID Record
 * Endpoint Identifier Record (not-in-use)
 * @see http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
 */

class EIDRecord extends RecordData {
	endpoint: Buffer;

	constructor() {
		super();
		this.endpoint = DUMMY;
	}

	get type() {
		return RecordType.EID;
	}

	getSize() {
		return this.endpoint.length;
	}

	write(bw) {
		bw.writeBytes(this.endpoint);
		return this;
	}

	read(br) {
		this.endpoint = br.readBytes(br.left());
		return this;
	}
}

/**
 * NIMLOC Record
 * Nimrod Locator Record (not-in-use)
 * @see http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
 */

class NIMLOCRecord extends RecordData {
	locator: Buffer;

	constructor() {
		super();
		this.locator = DUMMY;
	}

	get type() {
		return RecordType.NIMLOC;
	}

	getSize() {
		return this.locator.length;
	}

	write(bw) {
		bw.writeBytes(this.locator);
		return this;
	}

	read(br) {
		this.locator = br.readBytes(br.left());
		return this;
	}
}

/**
 * SRV Record
 * Service Locator Record
 * @see https://tools.ietf.org/html/rfc2782
 */

class SRVRecord extends RecordData {
	priority: number;
	weight: number;
	port: number;
	target: string;

	constructor() {
		super();
		this.priority = 0;
		this.weight = 0;
		this.port = 0;
		this.target = '.';
	}

	get type() {
		return RecordType.SRV;
	}

	canonical() {
		this.target = this.target.toLowerCase();
		return this;
	}

	getSize(map) {
		return 6 + sizeName(this.target, map);
	}

	write(bw, map) {
		bw.writeU16BE(this.priority);
		bw.writeU16BE(this.weight);
		bw.writeU16BE(this.port);
		writeNameBW(bw, this.target, map);
		return this;
	}

	read(br) {
		this.priority = br.readU16BE();
		this.weight = br.readU16BE();
		this.port = br.readU16BE();
		this.target = readNameBR(br);
		return this;
	}
}

/**
 * ATMA Record
 * Asynchronous Transfer Mode Record (not-in-use)
 * @see http://www.broadband-forum.org/ftp/pub/approved-specs/af-dans-0152.000.pdf
 */

class ATMARecord extends RecordData {
	// format: number; // TODO
	address: Buffer;

	constructor() {
		super();
		// this.format = 0;
		this.address = DUMMY;
	}

	get type() {
		return RecordType.ATMA;
	}

	getSize() {
		return 1 + this.address.length;
	}

	write(bw) {
		bw.writeU8(this.format);
		bw.writeBytes(this.address);
		return this;
	}

	read(br) {
		this.format = br.readU8();
		this.address = br.readBytes(br.left());
		return this;
	}
}

/**
 * NAPTR Record
 * Naming Authority Pointer Record
 * @see https://tools.ietf.org/html/rfc3403
 */

class NAPTRRecord extends RecordData {
	order: number;
	preference: number;
	flags: string;
	service: string;
	regexp: string;
	replacement: string;

	constructor() {
		super();
		this.order = 0;
		this.preference = 0;
		this.flags = '';
		this.service = '';
		this.regexp = '';
		this.replacement = '.';
	}

	get type() {
		return RecordType.NAPTR;
	}

	canonical() {
		this.replacement = this.replacement.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += 4;
		size += sizeString(this.flags);
		size += sizeString(this.service);
		size += sizeString(this.regexp);
		size += sizeName(this.replacement, map);
		return size;
	}

	write(bw, map) {
		bw.writeU16BE(this.order);
		bw.writeU16BE(this.preference);
		writeStringBW(bw, this.flags);
		writeStringBW(bw, this.service);
		writeStringBW(bw, this.regexp);
		writeNameBW(bw, this.replacement, map);
		return this;
	}

	read(br) {
		this.order = br.readU16BE();
		this.preference = br.readU16BE();
		this.flags = readStringBR(br);
		this.service = readStringBR(br);
		this.regexp = readStringBR(br);
		this.replacement = readNameBR(br);
		return this;
	}
}

/**
 * KX Record
 * Key Exchanger Record
 * @see https://tools.ietf.org/html/rfc2230
 */

class KXRecord extends RecordData {
	preference: number;
	exchanger: string;

	constructor() {
		super();
		this.preference = 0;
		this.exchanger = '.';
	}

	get type() {
		return RecordType.KX;
	}

	canonical() {
		this.exchanger = this.exchanger.toLowerCase();
		return this;
	}

	getSize(map) {
		return 2 + sizeName(this.exchanger, map);
	}

	write(bw, map) {
		bw.writeU16BE(this.preference);
		writeNameBW(bw, this.exchanger, map);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.exchanger = readNameBR(br);
		return this;
	}
}

/**
 * CERT Record
 * Certificate Record
 * @see https://tools.ietf.org/html/rfc4398
 */

class CERTRecord extends RecordData {
	certType: number;
	keyTag: number;
	algorithm: number;
	certificate: Buffer;

	constructor() {
		super();
		this.certType = 0;
		this.keyTag = 0;
		this.algorithm = 0;
		this.certificate = DUMMY;
	}

	get type() {
		return RecordType.CERT;
	}

	getSize() {
		return 5 + this.certificate.length;
	}

	write(bw) {
		bw.writeU16BE(this.certType);
		bw.writeU16BE(this.keyTag);
		bw.writeU8(this.algorithm);
		bw.writeBytes(this.certificate);
		return this;
	}

	read(br) {
		this.certType = br.readU16BE();
		this.keyTag = br.readU16BE();
		this.algorithm = br.readU8();
		this.certificate = br.readBytes(br.left());
		return this;
	}

	getJSON() {
		const typeName = CertType[this.certType];
		const json = super.getJSON();

		if (typeName)
			json.typeName = typeName;

		json.algName = algToString(this.algorithm);

		return json;
	}

	toString() {
		const typeName = CertType[this.certType];
		const algName = algToString(this.algorithm);

		let str = super.toString();

		str += ' ';

		if (typeName)
			str += ` ; cert type = ${typeName}`;

		str += ` ; alg = ${algName}`;

		return str;
	}
}

/**
 * A6Record
 * A IPv6 Record (historic)
 * @see https://tools.ietf.org/html/rfc2874#section-3.1.1
 * @see https://tools.ietf.org/html/rfc6563
 */

class A6Record extends RecordData {
	prefixLen: number;
	address: string;
	prefix: string;

	constructor() {
		super();
		this.prefixLen = 0;
		this.address = '::';
		this.prefix = '.';
	}

	get type() {
		return RecordType.A6;
	}

	canonical() {
		this.prefix = this.prefix.toLowerCase();
		return this;
	}

	getSize(map) {
		const len = this.prefixLen;
		assert(len <= 128);

		let size = 0;

		size += 1;
		size += (128 - len + 7) / 8 | 0;

		if (len > 0)
			size += sizeName(this.prefix, map);

		return size;
	}

	write(bw, map) {
		const len = this.prefixLen;
		assert(len <= 128);

		bw.writeU8(len);

		const size = (128 - len + 7) / 8 | 0;
		const ip = IP.toBuffer(this.address);

		bw.copy(ip, 16 - size, 16);

		if (len > 0)
			writeNameBW(bw, this.prefix, map);

		return this;
	}

	read(br) {
		const len = Math.min(128, br.readU8());
		const size = (128 - len + 7) / 8 | 0;
		const buf = br.readBytes(size, true);
		const ip = POOL16;

		ip.fill(0x00, 0, 16 - size);
		ip.copy(buf, 16 - size);

		this.prefixLen = len;
		this.address = IP.toString(ip);

		if (len > 0)
			this.prefix = readNameBR(br);

		return this;
	}
}

/**
 * DNAME Record
 * Delegation Name Record
 * @see https://tools.ietf.org/html/rfc6672
 */

class DNAMERecord extends CNAMERecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.DNAME;
	}
}

/**
 * OPT Record
 * Option Record (EDNS) (pseudo-record)
 * @see https://tools.ietf.org/html/rfc6891#section-6.1
 */

class OPTRecord extends RecordData {
	options: Option[];

	constructor() {
		super();
		this.options = [];
	}

	get type() {
		return RecordType.OPT;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		for (const opt of this.options)
			opt.canonical();
		return this;
	}

	getSize(map) {
		let size = 0;
		for (const opt of this.options)
			size += opt.getSize(map);
		return size;
	}

	write(bw, map) {
		for (const opt of this.options)
			opt.write(bw, map);
		return this;
	}

	read(br) {
		while (br.left())
			this.options.push(Option.read(br));
		return this;
	}

	toString() {
		return '';
	}

	fromString(str) {
		return this;
	}

	getJSON() {
		return {
			options: this.options.map(opt => opt.toJSON())
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert(Array.isArray(json.options));

		for (const opt of json.options)
			this.options.push(Option.fromJSON(opt));

		return this;
	}
}

/**
 * APL Record
 * Address Prefix List Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc3123
 */

class APLRecord extends RecordData {
	items: AP[];

	constructor() {
		super();
		this.items = [];
	}

	get type() {
		return RecordType.APL;
	}

	getSize() {
		let size = 0;

		for (const ap of this.items)
			size += ap.getSize();

		return size;
	}

	write(bw) {
		for (const ap of this.items)
			ap.write(bw);

		return this;
	}

	read(br) {
		while (br.left())
			this.items.push(AP.read(br));

		return this;
	}
}

/**
 * DS Record
 * Delegation Signer
 * @see https://tools.ietf.org/html/rfc4034
 */

class DSRecord extends RecordData {
	keyTag: number;
	algorithm: number;
	digestType: number;
	digest: Buffer;

	constructor() {
		super();
		this.keyTag = 0;
		this.algorithm = 0;
		this.digestType = 0;
		this.digest = DUMMY;
	}

	get type() {
		return RecordType.DS;
	}

	getSize() {
		return 4 + this.digest.length;
	}

	write(bw) {
		bw.writeU16BE(this.keyTag);
		bw.writeU8(this.algorithm);
		bw.writeU8(this.digestType);
		bw.writeBytes(this.digest);
		return this;
	}

	read(br) {
		this.keyTag = br.readU16BE();
		this.algorithm = br.readU8();
		this.digestType = br.readU8();
		this.digest = br.readBytes(br.left());
		return this;
	}

	getJSON() {
		const json = super.getJSON();
		json.algName = algToString(this.algorithm);
		json.hashName = hashToString(this.digestType);
		return json;
	}

	toString() {
		const algName = algToString(this.algorithm);
		const hashName = hashToString(this.digestType);

		let str = super.toString();

		// Mimic `delv`.
		str += ' ';
		str += ` ; alg = ${algName}`;
		str += ` ; hash = ${hashName}`;

		return str;
	}
}

/**
 * SSHFP Record
 * SSH Finger Print Record
 * @see https://tools.ietf.org/html/rfc4255
 */

class SSHFPRecord extends RecordData {
	algorithm: number;
	digestType: number;
	fingerprint: Buffer;

	constructor() {
		super();
		this.algorithm = 0;
		this.digestType = 0;
		this.fingerprint = DUMMY;
	}

	get type() {
		return RecordType.SSHFP;
	}

	getSize() {
		return 2 + this.fingerprint.length;
	}

	write(bw) {
		bw.writeU8(this.algorithm);
		bw.writeU8(this.digestType);
		bw.writeBytes(this.fingerprint);
		return this;
	}

	read(br) {
		this.algorithm = br.readU8();
		this.digestType = br.readU8();
		this.fingerprint = br.readBytes(br.left());
		return this;
	}

	getJSON() {
		const algName = SSHAlg[this.algorithm];
		const hashName = SSHHash[this.digestType];
		const json = super.getJSON();

		if (algName)
			json.algName = algName;

		if (hashName)
			json.hashName = hashName;

		return json;
	}

	toString() {
		const algName = SSHAlg[this.algorithm];
		const hashName = SSHHash[this.digestType];

		let str = super.toString();

		str += ' ';

		if (algName)
			str += ` ; alg = ${algName}`;

		if (hashName)
			str += ` ; hash = ${hashName}`;

		return str;
	}
}

/**
 * IPSECKEY Record
 * IPsec Key Record
 * @see https://tools.ietf.org/html/rfc4025
 */

class IPSECKEYRecord extends RecordData {
	precedence: number;
	gatewayType: number;
	algorithm: number;
	target: string;
	publicKey: Buffer;

	constructor() {
		super();
		this.precedence = 0;
		this.gatewayType = 1;
		this.algorithm = 0;
		this.target = '0.0.0.0';
		this.publicKey = DUMMY;
	}

	get type() {
		return RecordType.IPSECKEY;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		if (this.gatewayType === 3)
			this.target = this.target.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 3;

		switch (this.gatewayType) {
			case 1:
				size += 4;
				break;
			case 2:
				size += 16;
				break;
			case 3:
				size += sizeName(this.target, map);
				break;
		}

		size += this.publicKey.length;

		return size;
	}

	write(bw, map) {
		bw.writeU8(this.precedence);
		bw.writeU8(this.gatewayType);
		bw.writeU8(this.algorithm);

		switch (this.gatewayType) {
			case 1: {
				writeIP(bw, this.target, 4);
				break;
			}
			case 2: {
				writeIP(bw, this.target, 16);
				break;
			}
			case 3:
				writeNameBW(bw, this.target, map);
				break;
		}

		bw.writeBytes(this.publicKey);

		return this;
	}

	read(br) {
		this.precedence = br.readU8();
		this.gatewayType = br.readU8();
		this.algorithm = br.readU8();

		switch (this.gatewayType) {
			case 1:
				this.target = readIP(br, 4);
				break;
			case 2:
				this.target = readIP(br, 16);
				break;
			case 3:
				this.target = readNameBR(br);
				break;
		}

		this.publicKey = br.readBytes(br.left());

		return this;
	}
}

/**
 * RRSIG Record
 * DNSSEC Signature Record
 * @see https://tools.ietf.org/html/rfc4034
 */

class RRSIGRecord extends SIGRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.RRSIG;
	}
}

/**
 * NSEC Record
 * Next Secure Record
 * @see https://tools.ietf.org/html/rfc4034
 */

class NSECRecord extends RecordData {
	nextDomain: string;
	typeBitmap: Buffer;

	constructor() {
		super();
		this.nextDomain = '.';
		this.typeBitmap = DUMMY;
	}

	get type() {
		return RecordType.NSEC;
	}

	canonical() {
		this.nextDomain = this.nextDomain.toLowerCase();
		return this;
	}

	setTypes(types) {
		this.typeBitmap = toBitmap(types);
		return this;
	}

	getTypes() {
		return fromBitmap(this.typeBitmap);
	}

	hasType(type) {
		return hasType(this.typeBitmap, type);
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.nextDomain, map);
		size += this.typeBitmap.length;
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.nextDomain, map);
		bw.writeBytes(this.typeBitmap);
		return this;
	}

	read(br) {
		this.nextDomain = readNameBR(br);
		this.typeBitmap = br.readBytes(br.left());
		return this;
	}
}

/**
 * DNSKEY Record
 * DNS Key Record
 * @see https://tools.ietf.org/html/rfc4034
 */

class DNSKEYRecord extends KEYRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.DNSKEY;
	}
}

/**
 * DHCID Record
 * DHCP Identifier Record
 * @see https://tools.ietf.org/html/rfc4701
 */

class DHCIDRecord extends RecordData {
	digest: Buffer;

	constructor() {
		super();
		this.digest = DUMMY;
	}

	get type() {
		return RecordType.DHCID;
	}

	getSize() {
		return this.digest.length;
	}

	write(bw) {
		bw.writeBytes(this.digest);
		return this;
	}

	read(br) {
		this.digest = br.readBytes(br.left());
		return this;
	}
}

/**
 * NSEC3Record
 * Next Secure Record (v3)
 * @see https://tools.ietf.org/html/rfc5155
 */

class NSEC3Record extends RecordData {
	hash: number;
	flags: number;
	iterations: number;
	salt: Buffer;
	nextDomain: Buffer;
	typeBitmap: Buffer;

	constructor() {
		super();
		this.hash = 0;
		this.flags = 0;
		this.iterations = 0;
		this.salt = DUMMY;
		this.nextDomain = DUMMY;
		this.typeBitmap = DUMMY;
	}

	get type() {
		return RecordType.NSEC3;
	}

	setTypes(types) {
		this.typeBitmap = toBitmap(types);
		return this;
	}

	getTypes() {
		return fromBitmap(this.typeBitmap);
	}

	hasType(type) {
		return hasType(this.typeBitmap, type);
	}

	getSize() {
		let size = 0;
		size += 6;
		size += this.salt.length;
		size += this.nextDomain.length;
		size += this.typeBitmap.length;
		return size;
	}

	write(bw) {
		bw.writeU8(this.hash);
		bw.writeU8(this.flags);
		bw.writeU16BE(this.iterations);
		bw.writeU8(this.salt.length);
		bw.writeBytes(this.salt);
		bw.writeU8(this.nextDomain.length);
		bw.writeBytes(this.nextDomain);
		bw.writeBytes(this.typeBitmap);
		return this;
	}

	read(br) {
		this.hash = br.readU8();
		this.flags = br.readU8();
		this.iterations = br.readU16BE();
		this.salt = br.readBytes(br.readU8());
		this.nextDomain = br.readBytes(br.readU8());
		this.typeBitmap = br.readBytes(br.left());
		return this;
	}

	getJSON() {
		const hashName = NsecHash[this.hash];
		const json = super.getJSON();

		if (hashName)
			json.hashName = hashName;

		return json;
	}

	toString() {
		const hashName = NsecHash[this.hash];

		let str = super.toString();

		str += ' ';

		if (hashName)
			str += ` ; hash = ${hashName}`;

		return str;
	}
}

/**
 * NSEC3PARAM Record
 * NSEC3 Params Record
 * @see https://tools.ietf.org/html/rfc5155
 */

class NSEC3PARAMRecord extends RecordData {
	hash: number;
	flags: number;
	iterations: number;
	salt: Buffer;

	constructor() {
		super();
		this.hash = 0;
		this.flags = 0;
		this.iterations = 0;
		this.salt = DUMMY;
	}

	get type() {
		return RecordType.NSEC3PARAM;
	}

	getSize() {
		return 5 + this.salt.length;
	}

	write(bw) {
		bw.writeU8(this.hash);
		bw.writeU8(this.flags);
		bw.writeU16BE(this.iterations);
		bw.writeU8(this.salt.length);
		bw.writeBytes(this.salt);
		return this;
	}

	read(br) {
		this.hash = br.readU8();
		this.flags = br.readU8();
		this.iterations = br.readU16BE();
		this.salt = br.readBytes(br.readU8());
		return this;
	}

	getJSON() {
		const hashName = NsecHash[this.hash];
		const json = super.getJSON();

		if (hashName)
			json.hashName = hashName;

		return json;
	}

	toString() {
		const hashName = NsecHash[this.hash];

		let str = super.toString();

		str += ' ';

		if (hashName)
			str += ` ; hash = ${hashName}`;

		return str;
	}
}

/**
 * TLSA Record
 * TLSA Certificate Association Record
 * @see https://tools.ietf.org/html/rfc6698
 */

class TLSARecord extends RecordData {
	usage: number;
	selector: number;
	matchingType: number;
	certificate: Buffer;

	constructor() {
		super();
		this.usage = 0;
		this.selector = 0;
		this.matchingType = 0;
		this.certificate = DUMMY;
	}

	get type() {
		return RecordType.TLSA;
	}

	getSize() {
		return 3 + this.certificate.length;
	}

	write(bw) {
		bw.writeU8(this.usage);
		bw.writeU8(this.selector);
		bw.writeU8(this.matchingType);
		bw.writeBytes(this.certificate);
		return this;
	}

	read(br) {
		this.usage = br.readU8();
		this.selector = br.readU8();
		this.matchingType = br.readU8();
		this.certificate = br.readBytes(br.left());
		return this;
	}

	getJSON() {
		const usageName = DaneUsage[this.usage];
		const selectorName = DaneSelector[this.selector];
		const matchingTypeName = DaneMatchingType[this.matchingType];
		const json = super.getJSON();

		if (usageName)
			json.usageName = usageName;

		if (selectorName)
			json.selectorName = selectorName;

		if (matchingTypeName)
			json.matchingTypeName = matchingTypeName;

		return json;
	}

	toString() {
		const usageName = DaneUsage[this.usage];
		const selectorName = DaneSelector[this.selector];
		const matchingTypeName = DaneMatchingType[this.matchingType];

		let str = super.toString();

		str += ' ';

		if (usageName)
			str += ` ; usage = ${usageName}`;

		if (selectorName)
			str += ` ; selector = ${selectorName}`;

		if (matchingTypeName)
			str += ` ; matching type = ${matchingTypeName}`;

		return str;
	}
}

/**
 * SMIMEA Record
 * S/MIME Certificate Association Record
 * @see https://tools.ietf.org/html/rfc8162
 */

class SMIMEARecord extends TLSARecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.SMIMEA;
	}
}

/**
 * HIP Record
 * Host Identity Protocol Record
 * @see https://tools.ietf.org/html/rfc8005
 */

class HIPRecord extends RecordData {
	algorithm: number;
	hit: Buffer;
	publicKey: Buffer;
	servers: string[];

	constructor() {
		super();
		this.algorithm = 0;
		this.hit = DUMMY;
		this.publicKey = DUMMY;
		this.servers = [];
	}

	get type() {
		return RecordType.HIP;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		for (let i = 0; i < this.servers.length; i++)
			this.servers[i] = this.servers[i].toLowerCase();

		return this;
	}

	getSize(map) {
		let size = 4;
		size += this.hit.length;
		size += this.publicKey.length;
		for (const name of this.servers)
			size += sizeName(name, map);
		return size;
	}

	write(bw, map) {
		bw.writeU8(this.hit.length);
		bw.writeU8(this.algorithm);
		bw.writeU16BE(this.publicKey.length);
		bw.writeBytes(this.hit);
		bw.writeBytes(this.publicKey);
		for (const name of this.servers)
			writeNameBW(bw, name, map);
		return this;
	}

	read(br) {
		const hitLen = br.readU8();

		this.algorithm = br.readU8();

		const keyLen = br.readU16BE();

		this.hit = br.readBytes(hitLen);
		this.publicKey = br.readBytes(keyLen);

		while (br.left())
			this.servers.push(readNameBR(br));

		return this;
	}
}

/**
 * NINFO Record
 * Zone Status Information (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template
 * @see https://tools.ietf.org/html/draft-reid-dnsext-zs-01
 */

class NINFORecord extends RecordData {
	zsData: any[]; // TODO
	constructor() {
		super();
		this.zsData = [];
	}

	get type() {
		return RecordType.NINFO;
	}

	getSize() {
		let size = 0;
		for (const zs of this.zsData)
			size += sizeString(zs);
		return size;
	}

	write(bw) {
		for (const zs of this.zsData)
			writeStringBW(bw, zs);
		return this;
	}

	read(br) {
		while (br.left())
			this.zsData.push(readStringBR(br));
		return this;
	}
}

/**
 * RKEY Record
 * R Key Record (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template
 * @see https://tools.ietf.org/html/draft-reid-dnsext-rkey-00
 */

class RKEYRecord extends KEYRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.RKEY;
	}
}

/**
 * TALINK Record
 * Trust Authorities Link Record (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template
 * @see https://tools.ietf.org/html/draft-wijngaards-dnsop-trust-history-02
 */

class TALINKRecord extends RecordData {
	prevName: string;
	nextName: string;

	constructor() {
		super();
		this.prevName = '.';
		this.nextName = '.';
	}

	get type() {
		return RecordType.TALINK;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.prevName = this.prevName.toLowerCase();
		this.nextName = this.nextName.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.prevName, map);
		size += sizeName(this.nextName, map);
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.prevName, map);
		writeNameBW(bw, this.nextName, map);
		return this;
	}

	read(br) {
		this.prevName = readNameBR(br);
		this.nextName = readNameBR(br);
		return this;
	}
}

/**
 * CDS Record
 * Child DS Record
 * @see https://tools.ietf.org/html/rfc7344
 */

class CDSRecord extends DSRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.CDS;
	}
}

/**
 * CDNSKEY Record
 * Child DNSKEY Record
 * @see https://tools.ietf.org/html/rfc7344
 */

class CDNSKEYRecord extends KEYRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.CDNSKEY;
	}
}

/**
 * OPENPGPKEY Record
 * OpenPGP Public Key Record
 * @see https://tools.ietf.org/html/rfc7929
 */

class OPENPGPKEYRecord extends RecordData {
	publicKey: Buffer;

	constructor() {
		super();
		this.publicKey = DUMMY;
	}

	get type() {
		return RecordType.OPENPGPKEY;
	}

	getSize() {
		return this.publicKey.length;
	}

	write(bw) {
		bw.writeBytes(this.publicKey);
		return this;
	}

	read(br) {
		this.publicKey = br.readBytes(br.left());
		return this;
	}
}

/**
 * CSYNC Record
 * Child Synchronization Record
 * @see https://tools.ietf.org/html/rfc7477
 */

class CSYNCRecord extends RecordData {
	serial: number;
	flags: number;
	typeBitmap: Buffer;

	constructor() {
		super();
		this.serial = 0;
		this.flags = 0;
		this.typeBitmap = DUMMY;
	}

	get type() {
		return RecordType.CSYNC;
	}

	setTypes(types) {
		this.typeBitmap = toBitmap(types);
		return this;
	}

	getTypes() {
		return fromBitmap(this.typeBitmap);
	}

	hasType(type) {
		return hasType(this.typeBitmap, type);
	}

	getSize() {
		return 6 + this.typeBitmap.length;
	}

	write(bw) {
		bw.writeU32BE(this.serial);
		bw.writeU16BE(this.flags);
		bw.writeBytes(this.typeBitmap);
		return this;
	}

	read(br) {
		this.serial = br.readU32BE();
		this.flags = br.readU16BE();
		this.typeBitmap = br.readBytes(br.left());
		return this;
	}
}

/**
 * SPF Record
 * Sender Policy Framework Record (obsolete)
 * @see https://tools.ietf.org/html/rfc4408
 * @see https://tools.ietf.org/html/rfc7208
 */

class SPFRecord extends TXTRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.SPF;
	}
}

/**
 * UINFO Record
 * UINFO Record (obsolete)
 * (No Documentation)
 */

class UINFORecord extends RecordData {
	uinfo: string;

	constructor() {
		super();
		this.uinfo = '';
	}

	get type() {
		return RecordType.UINFO;
	}

	getSize() {
		return sizeString(this.uinfo);
	}

	write(bw) {
		writeStringBW(bw, this.uinfo);
		return this;
	}

	read(br) {
		this.uinfo = readStringBR(br);
		return this;
	}
}

/**
 * UID Record
 * UID Record (obsolete)
 * (No Documentation)
 */

class UIDRecord extends RecordData {
	uid: number;

	constructor() {
		super();
		this.uid = 0;
	}

	get type() {
		return RecordType.UID;
	}

	getSize() {
		return 4;
	}

	write(bw) {
		bw.writeU32BE(this.uid);
		return this;
	}

	read(br) {
		this.uid = br.readU32BE();
		return this;
	}
}

/**
 * GID Record
 * GID Record (obsolete)
 * (No Documentation)
 */

class GIDRecord extends RecordData {
	gid: number;

	constructor() {
		super();
		this.gid = 0;
	}

	get type() {
		return RecordType.GID;
	}

	getSize() {
		return 4;
	}

	write(bw) {
		bw.writeU32BE(this.gid);
		return this;
	}

	read(br) {
		this.gid = br.readU32BE();
		return this;
	}
}

/**
 * UNSPEC Record
 * UNSPEC Record (obsolete)
 * (No Documentation)
 */

class UNSPECRecord extends UNKNOWNRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.UNSPEC;
	}
}

/**
 * NID Record
 * Node Identifier Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class NIDRecord extends RecordData {
	preference: number;
	nodeID: Buffer;

	constructor() {
		super();
		this.preference = 0;
		this.nodeID = DUMMY8;
	}

	get type() {
		return RecordType.NID;
	}

	getSize() {
		return 10;
	}

	write(bw) {
		bw.writeU16BE(this.preference);
		bw.writeBytes(this.nodeID);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.nodeID = br.readBytes(8);
		return this;
	}
}

/**
 * L32Record
 * Locator 32 Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class L32Record extends RecordData {
	preference: number;
	locator32: Buffer;

	constructor() {
		super();
		this.preference = 0;
		this.locator32 = DUMMY4;
	}

	get type() {
		return RecordType.L32;
	}

	getSize() {
		return 6;
	}

	write(bw) {
		bw.writeU16BE(this.preference);
		bw.writeBytes(this.locator32);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.locator32 = br.readBytes(4);
		return this;
	}
}

/**
 * L64Record
 * Locator 64 Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class L64Record extends RecordData {
	preference: number;
	locator64: Buffer;

	constructor() {
		super();
		this.preference = 0;
		this.locator64 = DUMMY8;
	}

	get type() {
		return RecordType.L64;
	}

	getSize() {
		return 10;
	}

	write(bw) {
		bw.writeU16BE(this.preference);
		bw.writeBytes(this.locator64);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.locator64 = br.readBytes(8);
		return this;
	}
}

/**
 * LP Record
 * Locator Pointer Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class LPRecord extends RecordData {
	preference: number;
	fqdn: string;

	constructor() {
		super();
		this.preference = 0;
		this.fqdn = '.';
	}

	get type() {
		return RecordType.LP;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.fqdn = this.fqdn.toLowerCase();
		return this;
	}

	getSize(map) {
		return 2 + sizeName(this.fqdn, map);
	}

	write(bw, map) {
		bw.writeU16BE(this.preference);
		writeNameBW(bw, this.fqdn, map);
		return this;
	}

	read(br) {
		this.preference = br.readU16BE();
		this.fqdn = readNameBR(br);
		return this;
	}
}

/**
 * EUI48Record
 * Extended Unique Identifier Record (48 bit)
 * @see https://tools.ietf.org/html/rfc7043
 */

class EUI48Record extends RecordData {
	address: Buffer;

	constructor() {
		super();
		this.address = DUMMY6;
	}

	get type() {
		return RecordType.EUI48;
	}

	getSize() {
		return 6;
	}

	write(bw) {
		bw.writeBytes(this.address);
		return this;
	}

	read(br) {
		this.address = br.readBytes(6);
		return this;
	}
}

/**
 * EUI64Record
 * Extended Unique Identifier Record (64 bit)
 * @see https://tools.ietf.org/html/rfc7043
 */

class EUI64Record extends RecordData {
	address: Buffer;

	constructor() {
		super();
		this.address = DUMMY8;
	}

	get type() {
		return RecordType.EUI64;
	}

	getSize() {
		return 8;
	}

	write(bw) {
		bw.writeBytes(this.address);
		return this;
	}

	read(br) {
		this.address = br.readBytes(8);
		return this;
	}
}

/**
 * TKEY Record
 * Transaction Key Record
 * @see https://tools.ietf.org/html/rfc2930
 */

class TKEYRecord extends RecordData {
	algorithm: string;
	inception: number;
	expiration: number;
	mode: number;
	error: number;
	key: Buffer;
	other: Buffer;

	constructor() {
		super();
		this.algorithm = '.';
		this.inception = 0;
		this.expiration = 0;
		this.mode = 0;
		this.error = 0;
		this.key = DUMMY;
		this.other = DUMMY;
	}

	get type() {
		return RecordType.TKEY;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.algorithm = this.algorithm.toLowerCase();
		return this;
	}

	getSize(map) {
		let size = 0;
		size += sizeName(this.algorithm, map);
		size += 16;
		size += this.key.length;
		size += this.other.length;
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.algorithm, map);
		bw.writeU32BE(this.inception);
		bw.writeU32BE(this.expiration);
		bw.writeU16BE(this.mode);
		bw.writeU16BE(this.error);
		bw.writeU16BE(this.key.length);
		bw.writeBytes(this.key);
		bw.writeU16BE(this.other.length);
		bw.writeBytes(this.other);
		return this;
	}

	read(br) {
		this.algorithm = readNameBR(br);
		this.inception = br.readU32BE();
		this.expiration = br.readU32BE();
		this.mode = br.readU16BE();
		this.error = br.readU16BE();
		this.key = br.readBytes(br.readU16BE());
		this.other = br.readBytes(br.readU16BE());
		return this;
	}
}

/**
 * TSIG Record
 * Transaction Signature Record
 * @see https://tools.ietf.org/html/rfc2845
 */

class TSIGRecord extends RecordData {
	algorithm: string;
	timeSigned: number;
	fudge: number;
	mac: Buffer;
	origID: number;
	error: number;
	other: Buffer;

	constructor() {
		super();
		this.algorithm = '.';
		this.timeSigned = 0;
		this.fudge = 0;
		this.mac = DUMMY;
		this.origID = 0;
		this.error = 0;
		this.other = DUMMY;
	}

	get type() {
		return RecordType.TSIG;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.algorithm = this.algorithm.toLowerCase();
		return this;
	}

	getSize(map?) {
		let size = 16;
		size += sizeName(this.algorithm, map);
		size += this.mac.length;
		size += this.other.length;
		return size;
	}

	write(bw, map) {
		writeNameBW(bw, this.algorithm, map);
		bw.writeU16BE((this.timeSigned / 0x100000000) >>> 0);
		bw.writeU32BE(this.timeSigned >>> 0);
		bw.writeU16BE(this.fudge);
		bw.writeU16BE(this.mac.length);
		bw.writeBytes(this.mac);
		bw.writeU16BE(this.origID);
		bw.writeU16BE(this.error);
		bw.writeU16BE(this.other.length);
		bw.writeBytes(this.other);
		return this;
	}

	read(br) {
		this.algorithm = readNameBR(br);
		this.timeSigned = br.readU16BE() * 0x100000000 + br.readU32BE();
		this.fudge = br.readU16BE();
		this.mac = br.readBytes(br.readU16BE());
		this.origID = br.readU16BE();
		this.error = br.readU16BE();
		this.other = br.readBytes(br.readU16BE());
		return this;
	}

	getJSON() {
		const algorithm = this.algorithm.toLowerCase();
		const algName = tsigAlgsByVal[algorithm];
		const json = super.getJSON();

		if (algName)
			json.algName = algName;

		return json;
	}

	toString() {
		const algorithm = this.algorithm.toLowerCase();
		const algName = tsigAlgsByVal[algorithm];

		let str = super.toString();

		str += ' ';

		if (algName)
			str += ` ; alg = ${algName}`;

		return str;
	}
}

/**
 * URI Record
 * Uniform Resource Identifier Record
 * @see https://tools.ietf.org/html/rfc7553
 */

class URIRecord extends RecordData {
	priority: number;
	weight: number;
	target: string;

	constructor() {
		super();
		this.priority = 0;
		this.weight = 0;
		this.target = '';
	}

	get type() {
		return RecordType.URI;
	}

	getSize() {
		return 4 + sizeRawString(this.target);
	}

	write(bw) {
		bw.writeU16BE(this.priority);
		bw.writeU16BE(this.weight);
		writeRawStringBW(bw, this.target);
		return this;
	}

	read(br) {
		this.priority = br.readU16BE();
		this.weight = br.readU16BE();
		this.target = readRawStringBR(br, br.left(), true);
		return this;
	}
}

/**
 * CAA Record
 * Certification Authority Authorization Record
 * @see https://tools.ietf.org/html/rfc6844
 */

class CAARecord extends RecordData {
	flag: number;
	tag: string;
	value: string;

	constructor() {
		super();
		this.flag = 0;
		this.tag = '';
		this.value = '';
	}

	get type() {
		return RecordType.CAA;
	}

	getSize() {
		let size = 0;
		size += 1;
		size += sizeString(this.tag);
		size += sizeRawString(this.value);
		return size;
	}

	write(bw) {
		bw.writeU8(this.flag);
		writeStringBW(bw, this.tag);
		writeRawStringBW(bw, this.value);
		return this;
	}

	read(br) {
		this.flag = br.readU8();
		this.tag = readStringBR(br, true);
		this.value = readRawStringBR(br, br.left());
		return this;
	}
}

/**
 * AVC Record
 * Application Visibility and Control (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template
 */

class AVCRecord extends TXTRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.AVC;
	}
}

/**
 * DOA Record
 * Digital Object Architecture Record
 * @see https://www.ietf.org/archive/id/draft-durand-doa-over-dns-03.txt
 */

class DOARecord extends RecordData {
	enterprise: number;
	doa: number;
	location: number;
	mediaType: string;
	data: Buffer;

	constructor() {
		super();
		this.enterprise = 0;
		this.doa = 0;
		this.location = 0;
		this.mediaType = '';
		this.data = DUMMY;
	}

	get type() {
		return RecordType.DOA;
	}

	getSize() {
		let size = 0;
		size += 9;
		size += sizeString(this.mediaType);
		size += this.data.length;
		return size;
	}

	write(bw) {
		bw.writeU32BE(this.enterprise);
		bw.writeU32BE(this.doa);
		bw.writeU8(this.location);
		writeStringBW(bw, this.mediaType);
		bw.writeBytes(this.data);
		return this;
	}

	read(br) {
		this.enterprise = br.readU32BE();
		this.doa = br.readU32BE();
		this.location = br.readU8();
		this.mediaType = readStringBR(br);
		this.data = br.readBytes(br.left());
		return this;
	}
}

/**
 * TA Record
 * Trust Authorities Record
 * @see http://www.watson.org/~weiler/INI1999-19.pdf
 */

class TARecord extends RecordData {
	keyTag: number;
	algorithm: number;
	digestType: number;
	digest: Buffer;

	constructor() {
		super();
		this.keyTag = 0;
		this.algorithm = 0;
		this.digestType = 0;
		this.digest = DUMMY;
	}

	get type() {
		return RecordType.TA;
	}

	getSize() {
		return 4 + this.digest.length;
	}

	write(bw) {
		bw.writeU16BE(this.keyTag);
		bw.writeU8(this.algorithm);
		bw.writeU8(this.digestType);
		bw.writeBytes(this.digest);
		return this;
	}

	read(br) {
		this.keyTag = br.readU16BE();
		this.algorithm = br.readU8();
		this.digestType = br.readU8();
		this.digest = br.readBytes(br.left());
		return this;
	}
}

/**
 * DLV Record
 * DNSSEC Lookaside Validation Record
 * @see https://tools.ietf.org/html/rfc4431
 */

class DLVRecord extends DSRecord {
	constructor() {
		super();
	}

	get type() {
		return RecordType.DLV;
	}
}

/**
 * Option Field
 * @see https://tools.ietf.org/html/rfc6891#section-6.1
 */

class Option extends Struct {
	code: number;
	option: OptionData;

	constructor() {
		super();
		this.code = 0;
		this.option = new UNKNOWNOption();
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.option.canonical();
		return this;
	}

	getSize(map) {
		return 4 + this.option.getSize(map);
	}

	write(bw, map) {
		bw.writeU16BE(this.code);
		bw.writeU16BE(0);

		const off = bw.offset;

		this.option.write(bw, map);

		const size = bw.offset - off;

		bw.data.writeUInt16BE(size, off - 2, true);

		return this;
	}

	read(br) {
		this.code = br.readU16BE();

		const size = br.readU16BE();
		const child = br.readChild(size);

		this.option = readOption(this.code, child);

		return this;
	}

	toString() {
		const code = optionToString(this.code);
		const isUnknown = EOption[this.code] == null;

		let body = this.option.toString();

		if (isUnknown) {
			assert(this.option.code === EOption.RESERVED);
			const size = this.option.getSize().toString(10);
			body = `\\# ${size} ${body}`;
		}

		return `${code}: ${body}`;
	}

	fromString(str) {
		const scan = lazy(require, './scan');
		const op = scan.parseOption(exports, str);
		return this.inject(op);
	}

	getJSON() {
		return {
			code: optionToString(this.code),
			option: this.option.toJSON()
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert(json.option && typeof json.option === 'object');

		const code = stringToOption(json.code);
		const Option = optsByVal[code];

		let option;
		if (EOption[json.code] == null) {
			const data = util.parseHex(json.option.data);

			if (Option)
				option = Option.decode(data);
			else
				option = UNKNOWNOption.decode(data);
		} else {
			if (!Option)
				throw new Error(`Unknown option code: ${json.code}.`);

			option = Option.fromJSON(json.option);
		}

		this.code = code;
		this.option = option;

		return this;
	}
}

/**
 * OptionData
 */

class OptionData extends Struct {
	constructor() {
		super();
	}

	get code() {
		return EOption.RESERVED;
	}

	_schema() {
		const schema = lazy(require, './schema');
		const s = schema.options[this.code];

		if (!s)
			return schema.options[EOption.RESERVED];

		return s;
	}

	canonical() {
		return this;
	}

	toString() {
		const schema = lazy(require, './schema');
		return schema.toString(exports, this, this._schema());
	}

	fromString(str) {
		const scan = lazy(require, './scan');
		const od = scan.parseOptionData(exports, this.code, str);
		return this.inject(od);
	}

	getJSON() {
		const schema = lazy(require, './schema');
		return schema.toJSON(exports, this, this._schema());
	}

	fromJSON(json) {
		const schema = lazy(require, './schema');
		return schema.fromJSON(exports, this, this._schema(), json);
	}
}

/**
 * UNKNOWN Option
 * EDNS Unknown Option
 */

class UNKNOWNOption extends OptionData {
	data: Buffer;

	constructor() {
		super();
		this.data = DUMMY;
	}

	get code() {
		return EOption.RESERVED;
	}

	getSize(_?) {
		return this.data.length;
	}

	write(bw) {
		bw.writeBytes(this.data);
		return this;
	}

	read(br) {
		this.data = br.readBytes(br.left());
		return this;
	}
}

/**
 * LLQ Option
 * EDNS Long Lived Queries Option
 * @see http://tools.ietf.org/html/draft-sekar-dns-llq-01
 */

class LLQOption extends OptionData {
	version: number;
	opcode: number;
	error: number;
	id: Buffer;
	leaseLife: number;

	constructor() {
		super();
		this.version = 0;
		this.opcode = 0;
		this.error = 0;
		this.id = DUMMY8;
		this.leaseLife = 0;
	}

	get code() {
		return EOption.LLQ;
	}

	getSize() {
		return 18;
	}

	write(bw) {
		bw.writeU16BE(this.version);
		bw.writeU16BE(this.opcode);
		bw.writeU16BE(this.error);
		bw.writeBytes(this.id);
		bw.writeU32BE(this.leaseLife);
		return this;
	}

	read(br) {
		this.version = br.readU16BE();
		this.opcode = br.readU16BE();
		this.error = br.readU16BE();
		this.id = br.readBytes(8);
		this.leaseLife = br.readU32BE();
		return this;
	}
}

/**
 * UL Option
 * EDNS Update Lease Option
 * @see http://files.dns-sd.org/draft-sekar-dns-ul.txt
 */

class ULOption extends OptionData {
	lease: number;

	constructor() {
		super();
		this.lease = 0;
	}

	get code() {
		return EOption.UL;
	}

	getSize() {
		return 4;
	}

	write(bw) {
		bw.writeU32BE(this.lease);
		return this;
	}

	read(br) {
		this.lease = br.readU32BE();
		return this;
	}
}

/**
 * NSID Option
 * Nameserver Identifier Option
 * @see https://tools.ietf.org/html/rfc5001
 */

class NSIDOption extends OptionData {
	nsid: Buffer;

	constructor() {
		super();
		this.nsid = DUMMY;
	}

	get code() {
		return EOption.NSID;
	}

	getSize() {
		return this.nsid.length;
	}

	write(bw) {
		bw.writeBytes(this.nsid);
		return this;
	}

	read(br) {
		this.nsid = br.readBytes(br.left());
		return this;
	}
}

/**
 * DAU Option
 * EDNS DNSSEC Algorithm Understood Option
 * @see https://tools.ietf.org/html/rfc6975
 */

class DAUOption extends OptionData {
	algCode: Buffer;

	constructor() {
		super();
		this.algCode = DUMMY;
	}

	get code() {
		return EOption.DAU;
	}

	getSize() {
		return this.algCode.length;
	}

	write(bw) {
		bw.writeBytes(this.algCode);
		return this;
	}

	read(br) {
		this.algCode = br.readBytes(br.left());
		return this;
	}
}

/**
 * DHU Option
 * EDNS DS Hash Understood Option
 * @see https://tools.ietf.org/html/rfc6975
 */

class DHUOption extends DAUOption {
	constructor() {
		super();
	}

	get code() {
		return EOption.DHU;
	}
}

/**
 * N3U Option
 * EDNS NSEC3 Hash Understood Option
 * @see https://tools.ietf.org/html/rfc6975
 */

class N3UOption extends DAUOption {
	constructor() {
		super();
	}

	get code() {
		return EOption.N3U;
	}
}

/**
 * SUBNET Option
 * EDNS Subnet Option
 * @see https://tools.ietf.org/html/rfc7871
 */

class SUBNETOption extends OptionData {
	family: number;
	sourceNetmask: number;
	sourceScope: number;
	address: string;
	data: Buffer;

	constructor() {
		super();
		this.family = 1;
		this.sourceNetmask = 0;
		this.sourceScope = 0;
		this.address = '0.0.0.0';
		this.data = DUMMY;
	}

	get code() {
		return EOption.SUBNET;
	}

	getSize() {
		switch (this.family) {
			case 1:
				return 4 + 4;
			case 2:
				return 4 + 16;
			default:
				return 4 + this.data.length;
		}
	}

	write(bw) {
		bw.writeU16BE(this.family);
		bw.writeU8(this.sourceNetmask);
		bw.writeU8(this.sourceScope);

		switch (this.family) {
			case 1: {
				writeIP(bw, this.address, 4);
				break;
			}
			case 2: {
				writeIP(bw, this.address, 16);
				break;
			}
			default: {
				bw.writeBytes(this.data);
				break;
			}
		}

		return this;
	}

	read(br) {
		this.family = br.readU16BE();
		this.sourceNetmask = br.readU8();
		this.sourceScope = br.readU8();

		switch (this.family) {
			case 1:
				this.address = readIP(br, 4);
				break;
			case 2:
				this.address = readIP(br, 16);
				break;
			default:
				this.data = br.readBytes(br.left());
				break;
		}

		return this;
	}
}

/**
 * EXPIRE Option
 * EDNS Expire Option
 * @see https://tools.ietf.org/html/rfc7314
 */

class EXPIREOption extends OptionData {
	expire: number;

	constructor() {
		super();
		this.expire = 0;
	}

	get code() {
		return EOption.EXPIRE;
	}

	getSize() {
		return 4;
	}

	write(bw) {
		bw.writeU32BE(this.expire);
		return this;
	}

	read(br) {
		this.expire = br.readU32BE();
		return this;
	}
}

/**
 * COOKIE Option
 * EDNS Cookie Option
 * @see https://tools.ietf.org/html/rfc7873
 */

class COOKIEOption extends OptionData {
	cookie: Buffer;

	constructor() {
		super();
		this.cookie = DUMMY;
	}

	get code() {
		return EOption.COOKIE;
	}

	getSize() {
		return this.cookie.length;
	}

	write(bw) {
		bw.writeBytes(this.cookie);
		return this;
	}

	read(br) {
		this.cookie = br.readBytes(br.left());
		return this;
	}
}

/**
 * TCPKEEPALIVE Option
 * EDNS TCP Keep-Alive Option
 * @see https://tools.ietf.org/html/rfc7828
 */

class TCPKEEPALIVEOption extends OptionData {
	length: number;
	timeout: number;

	constructor() {
		super();
		this.length = 0;
		this.timeout = 0;
	}

	get code() {
		return EOption.TCPKEEPALIVE;
	}

	getSize() {
		return 4;
	}

	write(bw) {
		bw.writeU16BE(this.length);
		bw.writeU16BE(this.timeout);
		return this;
	}

	read(br) {
		this.length = br.readU16BE();
		this.timeout = br.readU16BE();
		return this;
	}
}

/**
 * PADDING Option
 * EDNS Padding Option
 * @see https://tools.ietf.org/html/rfc7830
 */

class PADDINGOption extends OptionData {
	padding: Buffer;

	constructor() {
		super();
		this.padding = DUMMY;
	}

	get code() {
		return EOption.PADDING;
	}

	getSize() {
		return this.padding.length;
	}

	write(bw) {
		bw.writeBytes(this.padding);
		return this;
	}

	read(br) {
		this.padding = br.readBytes(br.left());
		return this;
	}
}

/**
 * CHAIN Option
 * EDNS Chain Option
 * @see https://tools.ietf.org/html/rfc7901
 */

class CHAINOption extends OptionData {
	trustPoint: string;

	constructor() {
		super();
		this.trustPoint = '.';
	}

	get code() {
		return EOption.CHAIN;
	}

	canonical() {
		// Note: not mentioned in RFC 4034.
		this.trustPoint = this.trustPoint.toLowerCase();
		return this;
	}

	getSize(map) {
		return sizeName(this.trustPoint, map);
	}

	write(bw, map) {
		writeNameBW(bw, this.trustPoint, map);
		return this;
	}

	read(br) {
		this.trustPoint = readNameBR(br);
		return this;
	}
}

/**
 * KEYTAG Option
 * EDNS Key Tag Option
 * @see https://tools.ietf.org/html/rfc8145
 */

class KEYTAGOption extends OptionData {
	private tags: number[];

	constructor() {
		super();
		this.tags = [];
	}

	get code() {
		return EOption.KEYTAG;
	}

	getSize() {
		return this.tags.length * 2;
	}

	write(bw) {
		for (const tag of this.tags)
			bw.writeU16BE(tag);
		return this;
	}

	read(br) {
		while (br.left())
			this.tags.push(br.readU16BE());
		return this;
	}
}

/**
 * LOCAL Option
 * EDNS Local Option
 * @see https://tools.ietf.org/html/rfc6891
 */

class LOCALOption extends OptionData {
	data: Buffer;

	constructor() {
		super();
		this.data = DUMMY;
	}

	get code() {
		return EOption.LOCAL;
	}

	getSize() {
		return this.data.length;
	}

	write(bw) {
		bw.writeBytes(this.data);
		return this;
	}

	read(br) {
		this.data = br.readBytes(br.left());
		return this;
	}
}

/**
 * Address Prefix
 * Used for APL Records
 * @see https://tools.ietf.org/html/rfc3123
 */

class AP extends Struct {
	family: number;
	prefix: number;
	n: number;
	afd: Buffer;

	constructor() {
		super();
		this.family = 1;
		this.prefix = 0;
		this.n = 0;
		this.afd = DUMMY4;
	}

	getSize() {
		return 4 + this.afd.length;
	}

	write(bw) {
		bw.writeU16BE(this.family);
		bw.writeU8(this.prefix);
		bw.writeU8((this.n << 7) | this.afd.length);
		bw.writeBytes(this.afd);
		return this;
	}

	read(br) {
		const family = br.readU16BE();
		const prefix = br.readU8();

		const field = br.readU8();
		const n = field >>> 7;
		const len = field & 0x7f;
		const afd = br.readBytes(len);

		this.family = family;
		this.prefix = prefix;
		this.n = n;
		this.afd = afd;

		return this;
	}

	getJSON() {
		return {
			family: this.family,
			prefix: this.prefix,
			n: this.n,
			afd: this.afd.toString('hex')
		};
	}

	fromJSON(json) {
		assert(json && typeof json === 'object');
		assert((json.family & 0xff) === json.family);
		assert((json.prefix & 0xff) === json.prefix);
		assert((json.n & 1) === json.n);

		this.family = json.family;
		this.prefix = json.prefix;
		this.n = json.n;
		this.afd = util.parseHex(json.afd);

		return this;
	}

	getAFD() {
		if (this.family === 1) {
			const afd = util.padRight(this.afd, 4);
			return IP.toString(afd);
		}

		if (this.family === 2) {
			const afd = util.padRight(this.afd, 16);

			if (IP.isIPv4(afd))
				return `::ffff:${IP.toString(afd)}`;

			return IP.toString(afd);
		}

		return this.afd.toString('hex');
	}

	setAFD(addr) {
		if (this.family === 1) {
			const ip = IP.toBuffer(addr);

			if (!IP.isIPv4(ip))
				throw new Error('Invalid AFD.');

			this.afd = ip;

			return this;
		}

		if (this.family === 2) {
			this.afd = IP.toBuffer(addr);
			return this;
		}

		this.afd = util.parseHex(addr);

		return this;
	}

	toString() {
		let str = '';

		if (this.n)
			str += '!';

		str += this.family.toString(10);
		str += ':';
		str += this.getAFD();
		str += '/';
		str += this.prefix;

		return str;
	}

	fromString(str) {
		assert(typeof str === 'string');
		assert(str.length <= 265);

		let n = 0;

		// {[!]afi:address/prefix}
		if (str.length > 0 && str[0] === '!') {
			str = str.substring(1);
			n = 1;
		}

		const colon = str.indexOf(':');
		assert(colon !== -1);

		const afi = str.substring(0, colon);
		const rest = str.substring(colon + 1);

		const slash = rest.indexOf('/');
		assert(slash !== -1);

		const addr = rest.substring(0, slash);
		const prefix = rest.substring(slash + 1);

		this.family = util.parseU8(afi);
		this.prefix = util.parseU8(prefix);
		this.n = n;
		this.setAFD(addr);

		return this;
	}
}

/**
 * Record Classes
 * @const {Object}
 */

records = {
	UNKNOWN: UNKNOWNRecord,
	A: ARecord,
	NS: NSRecord,
	MD: MDRecord,
	MF: MFRecord,
	CNAME: CNAMERecord,
	SOA: SOARecord,
	MB: MBRecord,
	MG: MGRecord,
	MR: MRRecord,
	NULL: NULLRecord,
	WKS: WKSRecord,
	PTR: PTRRecord,
	HINFO: HINFORecord,
	MINFO: MINFORecord,
	MX: MXRecord,
	TXT: TXTRecord,
	RP: RPRecord,
	AFSDB: AFSDBRecord,
	X25: X25Record,
	ISDN: ISDNRecord,
	RT: RTRecord,
	NSAP: NSAPRecord,
	NSAPPTR: NSAPPTRRecord,
	SIG: SIGRecord,
	KEY: KEYRecord,
	PX: PXRecord,
	GPOS: GPOSRecord,
	AAAA: AAAARecord,
	LOC: LOCRecord,
	NXT: NXTRecord,
	EID: EIDRecord,
	NIMLOC: NIMLOCRecord,
	SRV: SRVRecord,
	ATMA: ATMARecord,
	NAPTR: NAPTRRecord,
	KX: KXRecord,
	CERT: CERTRecord,
	A6: A6Record,
	DNAME: DNAMERecord,
	SINK: null,
	OPT: OPTRecord,
	APL: APLRecord,
	DS: DSRecord,
	SSHFP: SSHFPRecord,
	IPSECKEY: IPSECKEYRecord,
	RRSIG: RRSIGRecord,
	NSEC: NSECRecord,
	DNSKEY: DNSKEYRecord,
	DHCID: DHCIDRecord,
	NSEC3: NSEC3Record,
	NSEC3PARAM: NSEC3PARAMRecord,
	TLSA: TLSARecord,
	SMIMEA: SMIMEARecord,
	HIP: HIPRecord,
	NINFO: NINFORecord,
	RKEY: RKEYRecord,
	TALINK: TALINKRecord,
	CDS: CDSRecord,
	CDNSKEY: CDNSKEYRecord,
	OPENPGPKEY: OPENPGPKEYRecord,
	CSYNC: CSYNCRecord,
	SPF: SPFRecord,
	UINFO: UINFORecord,
	UID: UIDRecord,
	GID: GIDRecord,
	UNSPEC: UNSPECRecord,
	NID: NIDRecord,
	L32: L32Record,
	L64: L64Record,
	LP: LPRecord,
	EUI48: EUI48Record,
	EUI64: EUI64Record,
	TKEY: TKEYRecord,
	TSIG: TSIGRecord,
	URI: URIRecord,
	CAA: CAARecord,
	AVC: AVCRecord,
	DOA: DOARecord,
	IXFR: null,
	AXFR: null,
	MAILB: null,
	MAILA: null,
	ANY: null,
	TA: TARecord,
	DLV: DLVRecord,
	RESERVED: null
};

/**
 * Record Classes By Value
 * @const {Object}
 */

recordsByVal = {
	[RecordType.UNKNOWN]: UNKNOWNRecord,
	[RecordType.A]: ARecord,
	[RecordType.NS]: NSRecord,
	[RecordType.MD]: MDRecord,
	[RecordType.MF]: MFRecord,
	[RecordType.CNAME]: CNAMERecord,
	[RecordType.SOA]: SOARecord,
	[RecordType.MB]: MBRecord,
	[RecordType.MG]: MGRecord,
	[RecordType.MR]: MRRecord,
	[RecordType.NULL]: NULLRecord,
	[RecordType.WKS]: WKSRecord,
	[RecordType.PTR]: PTRRecord,
	[RecordType.HINFO]: HINFORecord,
	[RecordType.MINFO]: MINFORecord,
	[RecordType.MX]: MXRecord,
	[RecordType.TXT]: TXTRecord,
	[RecordType.RP]: RPRecord,
	[RecordType.AFSDB]: AFSDBRecord,
	[RecordType.X25]: X25Record,
	[RecordType.ISDN]: ISDNRecord,
	[RecordType.RT]: RTRecord,
	[RecordType.NSAP]: NSAPRecord,
	[RecordType.NSAPPTR]: NSAPPTRRecord,
	[RecordType.SIG]: SIGRecord,
	[RecordType.KEY]: KEYRecord,
	[RecordType.PX]: PXRecord,
	[RecordType.GPOS]: GPOSRecord,
	[RecordType.AAAA]: AAAARecord,
	[RecordType.LOC]: LOCRecord,
	[RecordType.NXT]: NXTRecord,
	[RecordType.EID]: EIDRecord,
	[RecordType.NIMLOC]: NIMLOCRecord,
	[RecordType.SRV]: SRVRecord,
	[RecordType.ATMA]: ATMARecord,
	[RecordType.NAPTR]: NAPTRRecord,
	[RecordType.KX]: KXRecord,
	[RecordType.CERT]: CERTRecord,
	[RecordType.A6]: A6Record,
	[RecordType.DNAME]: DNAMERecord,
	[RecordType.SINK]: null,
	[RecordType.OPT]: OPTRecord,
	[RecordType.APL]: APLRecord,
	[RecordType.DS]: DSRecord,
	[RecordType.SSHFP]: SSHFPRecord,
	[RecordType.IPSECKEY]: IPSECKEYRecord,
	[RecordType.RRSIG]: RRSIGRecord,
	[RecordType.NSEC]: NSECRecord,
	[RecordType.DNSKEY]: DNSKEYRecord,
	[RecordType.DHCID]: DHCIDRecord,
	[RecordType.NSEC3]: NSEC3Record,
	[RecordType.NSEC3PARAM]: NSEC3PARAMRecord,
	[RecordType.TLSA]: TLSARecord,
	[RecordType.SMIMEA]: SMIMEARecord,
	[RecordType.HIP]: HIPRecord,
	[RecordType.NINFO]: NINFORecord,
	[RecordType.RKEY]: RKEYRecord,
	[RecordType.TALINK]: TALINKRecord,
	[RecordType.CDS]: CDSRecord,
	[RecordType.CDNSKEY]: CDNSKEYRecord,
	[RecordType.OPENPGPKEY]: OPENPGPKEYRecord,
	[RecordType.CSYNC]: CSYNCRecord,
	[RecordType.SPF]: SPFRecord,
	[RecordType.UINFO]: UINFORecord,
	[RecordType.UID]: UIDRecord,
	[RecordType.GID]: GIDRecord,
	[RecordType.UNSPEC]: UNSPECRecord,
	[RecordType.NID]: NIDRecord,
	[RecordType.L32]: L32Record,
	[RecordType.L64]: L64Record,
	[RecordType.LP]: LPRecord,
	[RecordType.EUI48]: EUI48Record,
	[RecordType.EUI64]: EUI64Record,
	[RecordType.TKEY]: TKEYRecord,
	[RecordType.TSIG]: TSIGRecord,
	[RecordType.URI]: URIRecord,
	[RecordType.CAA]: CAARecord,
	[RecordType.AVC]: AVCRecord,
	[RecordType.DOA]: DOARecord,
	[RecordType.IXFR]: null,
	[RecordType.AXFR]: null,
	[RecordType.MAILB]: null,
	[RecordType.MAILA]: null,
	[RecordType.ANY]: null,
	[RecordType.TA]: TARecord,
	[RecordType.DLV]: DLVRecord,
	[RecordType.RESERVED]: null
};

/**
 * EDNS0 Option Classes
 * @const {Object}
 */

opts = {
	UNKNOWN: UNKNOWNOption,
	LLQ: LLQOption,
	UL: ULOption,
	NSID: NSIDOption,
	DAU: DAUOption,
	DHU: DHUOption,
	N3U: N3UOption,
	SUBNET: SUBNETOption,
	EXPIRE: EXPIREOption,
	COOKIE: COOKIEOption,
	TCPKEEPALIVE: TCPKEEPALIVEOption,
	PADDING: PADDINGOption,
	CHAIN: CHAINOption,
	KEYTAG: KEYTAGOption,
	LOCAL: LOCALOption,
	LOCALSTART: LOCALOption,
	LOCALEND: LOCALOption
};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

optsByVal = {
	[EOption.RESERVED]: UNKNOWNOption,
	[EOption.LLQ]: LLQOption,
	[EOption.UL]: ULOption,
	[EOption.NSID]: NSIDOption,
	[EOption.DAU]: DAUOption,
	[EOption.DHU]: DHUOption,
	[EOption.N3U]: N3UOption,
	[EOption.SUBNET]: SUBNETOption,
	[EOption.EXPIRE]: EXPIREOption,
	[EOption.COOKIE]: COOKIEOption,
	[EOption.TCPKEEPALIVE]: TCPKEEPALIVEOption,
	[EOption.PADDING]: PADDINGOption,
	[EOption.CHAIN]: CHAINOption,
	[EOption.KEYTAG]: KEYTAGOption,
	[EOption.LOCAL]: LOCALOption,
	[EOption.LOCALSTART]: LOCALOption,
	[EOption.LOCALEND]: LOCALOption
};

/*
 * Decode
 */

function decodeData(type, data) {
	return readData(type, bio.read(data));
}

function readData(type: RecordType.A, br: BufferReader): ARecord;
function readData(type: RecordType.NS, br: BufferReader): NSRecord;
function readData(type: RecordType.MD, br: BufferReader): MDRecord;
function readData(type: RecordType.MF, br: BufferReader): MFRecord;
function readData(type: RecordType.CNAME, br: BufferReader): CNAMERecord;
function readData(type: RecordType.SOA, br: BufferReader): SOARecord;
function readData(type: RecordType.MB, br: BufferReader): MBRecord;
function readData(type: RecordType.MG, br: BufferReader): MGRecord;
function readData(type: RecordType.MR, br: BufferReader): MRRecord;
function readData(type: RecordType.NULL, br: BufferReader): NULLRecord;
function readData(type: RecordType.WKS, br: BufferReader): WKSRecord;
function readData(type: RecordType.PTR, br: BufferReader): PTRRecord;
function readData(type: RecordType.HINFO, br: BufferReader): HINFORecord;
function readData(type: RecordType.MINFO, br: BufferReader): MINFORecord;
function readData(type: RecordType.MX, br: BufferReader): MXRecord;
function readData(type: RecordType.TXT, br: BufferReader): TXTRecord;
function readData(type: RecordType.RP, br: BufferReader): RPRecord;
function readData(type: RecordType.AFSDB, br: BufferReader): AFSDBRecord;
function readData(type: RecordType.X25, br: BufferReader): X25Record;
function readData(type: RecordType.ISDN, br: BufferReader): ISDNRecord;
function readData(type: RecordType.RT, br: BufferReader): RTRecord;
function readData(type: RecordType.NSAP, br: BufferReader): NSAPRecord;
function readData(type: RecordType.NSAPPTR, br: BufferReader): NSAPPTRRecord;
function readData(type: RecordType.SIG, br: BufferReader): SIGRecord;
function readData(type: RecordType.KEY, br: BufferReader): KEYRecord;
function readData(type: RecordType.PX, br: BufferReader): PXRecord;
function readData(type: RecordType.GPOS, br: BufferReader): GPOSRecord;
function readData(type: RecordType.AAAA, br: BufferReader): AAAARecord;
function readData(type: RecordType.LOC, br: BufferReader): LOCRecord;
function readData(type: RecordType.NXT, br: BufferReader): NXTRecord;
function readData(type: RecordType.EID, br: BufferReader): EIDRecord;
function readData(type: RecordType.NIMLOC, br: BufferReader): NIMLOCRecord;
function readData(type: RecordType.SRV, br: BufferReader): SRVRecord;
function readData(type: RecordType.ATMA, br: BufferReader): ATMARecord;
function readData(type: RecordType.NAPTR, br: BufferReader): NAPTRRecord;
function readData(type: RecordType.KX, br: BufferReader): KXRecord;
function readData(type: RecordType.CERT, br: BufferReader): CERTRecord;
function readData(type: RecordType.A6, br: BufferReader): A6Record;
function readData(type: RecordType.DNAME, br: BufferReader): DNAMERecord;
function readData(type: RecordType.OPT, br: BufferReader): OPTRecord;
function readData(type: RecordType.APL, br: BufferReader): APLRecord;
function readData(type: RecordType.DS, br: BufferReader): DSRecord;
function readData(type: RecordType.SSHFP, br: BufferReader): SSHFPRecord;
function readData(type: RecordType.IPSECKEY, br: BufferReader): IPSECKEYRecord;
function readData(type: RecordType.RRSIG, br: BufferReader): RRSIGRecord;
function readData(type: RecordType.NSEC, br: BufferReader): NSECRecord;
function readData(type: RecordType.DNSKEY, br: BufferReader): DNSKEYRecord;
function readData(type: RecordType.DHCID, br: BufferReader): DHCIDRecord;
function readData(type: RecordType.NSEC3, br: BufferReader): NSEC3Record;
function readData(type: RecordType.NSEC3PARAM, br: BufferReader): NSEC3PARAMRecord;
function readData(type: RecordType.TLSA, br: BufferReader): TLSARecord;
function readData(type: RecordType.SMIMEA, br: BufferReader): SMIMEARecord;
function readData(type: RecordType.HIP, br: BufferReader): HIPRecord;
function readData(type: RecordType.NINFO, br: BufferReader): NINFORecord;
function readData(type: RecordType.RKEY, br: BufferReader): RKEYRecord;
function readData(type: RecordType.TALINK, br: BufferReader): TALINKRecord;
function readData(type: RecordType.CDS, br: BufferReader): CDSRecord;
function readData(type: RecordType.CDNSKEY, br: BufferReader): CDNSKEYRecord;
function readData(type: RecordType.OPENPGPKEY, br: BufferReader): OPENPGPKEYRecord;
function readData(type: RecordType.CSYNC, br: BufferReader): CSYNCRecord;
function readData(type: RecordType.SPF, br: BufferReader): SPFRecord;
function readData(type: RecordType.UINFO, br: BufferReader): UINFORecord;
function readData(type: RecordType.UID, br: BufferReader): UIDRecord;
function readData(type: RecordType.GID, br: BufferReader): GIDRecord;
function readData(type: RecordType.UNSPEC, br: BufferReader): UNSPECRecord;
function readData(type: RecordType.NID, br: BufferReader): NIDRecord;
function readData(type: RecordType.L32, br: BufferReader): L32Record;
function readData(type: RecordType.L64, br: BufferReader): L64Record;
function readData(type: RecordType.LP, br: BufferReader): LPRecord;
function readData(type: RecordType.EUI48, br: BufferReader): EUI48Record;
function readData(type: RecordType.EUI64, br: BufferReader): EUI64Record;
function readData(type: RecordType.TKEY, br: BufferReader): TKEYRecord;
function readData(type: RecordType.TSIG, br: BufferReader): TSIGRecord;
function readData(type: RecordType.URI, br: BufferReader): URIRecord;
function readData(type: RecordType.CAA, br: BufferReader): CAARecord;
function readData(type: RecordType.AVC, br: BufferReader): AVCRecord;
function readData(type: RecordType.DOA, br: BufferReader): DOARecord;
function readData(type: RecordType.TA, br: BufferReader): TARecord;
function readData(type: RecordType.DLV, br: BufferReader): DLVRecord;
function readData(type: RecordType, br: BufferReader): RecordData;
function readData(type: RecordType, br: BufferReader): RecordData {
	assert((type & 0xffff) === type);

	switch (type) {
		case RecordType.A:
			return ARecord.read(br);
		case RecordType.NS:
			return NSRecord.read(br);
		case RecordType.MD:
			return MDRecord.read(br);
		case RecordType.MF:
			return MFRecord.read(br);
		case RecordType.CNAME:
			return CNAMERecord.read(br);
		case RecordType.SOA:
			return SOARecord.read(br);
		case RecordType.MB:
			return MBRecord.read(br);
		case RecordType.MG:
			return MGRecord.read(br);
		case RecordType.MR:
			return MRRecord.read(br);
		case RecordType.NULL:
			return NULLRecord.read(br);
		case RecordType.WKS:
			return WKSRecord.read(br);
		case RecordType.PTR:
			return PTRRecord.read(br);
		case RecordType.HINFO:
			return HINFORecord.read(br);
		case RecordType.MINFO:
			return MINFORecord.read(br);
		case RecordType.MX:
			return MXRecord.read(br);
		case RecordType.TXT:
			return TXTRecord.read(br);
		case RecordType.RP:
			return RPRecord.read(br);
		case RecordType.AFSDB:
			return AFSDBRecord.read(br);
		case RecordType.X25:
			return X25Record.read(br);
		case RecordType.ISDN:
			return ISDNRecord.read(br);
		case RecordType.RT:
			return RTRecord.read(br);
		case RecordType.NSAP:
			return NSAPRecord.read(br);
		case RecordType.NSAPPTR:
			return NSAPPTRRecord.read(br);
		case RecordType.SIG:
			return SIGRecord.read(br);
		case RecordType.KEY:
			return KEYRecord.read(br);
		case RecordType.PX:
			return PXRecord.read(br);
		case RecordType.GPOS:
			return GPOSRecord.read(br);
		case RecordType.AAAA:
			return AAAARecord.read(br);
		case RecordType.LOC:
			return LOCRecord.read(br);
		case RecordType.NXT:
			return NXTRecord.read(br);
		case RecordType.EID:
			return EIDRecord.read(br);
		case RecordType.NIMLOC:
			return NIMLOCRecord.read(br);
		case RecordType.SRV:
			return SRVRecord.read(br);
		case RecordType.ATMA:
			return ATMARecord.read(br);
		case RecordType.NAPTR:
			return NAPTRRecord.read(br);
		case RecordType.KX:
			return KXRecord.read(br);
		case RecordType.CERT:
			return CERTRecord.read(br);
		case RecordType.A6:
			return A6Record.read(br);
		case RecordType.DNAME:
			return DNAMERecord.read(br);
		case RecordType.OPT:
			return OPTRecord.read(br);
		case RecordType.APL:
			return APLRecord.read(br);
		case RecordType.DS:
			return DSRecord.read(br);
		case RecordType.SSHFP:
			return SSHFPRecord.read(br);
		case RecordType.IPSECKEY:
			return IPSECKEYRecord.read(br);
		case RecordType.RRSIG:
			return RRSIGRecord.read(br);
		case RecordType.NSEC:
			return NSECRecord.read(br);
		case RecordType.DNSKEY:
			return DNSKEYRecord.read(br);
		case RecordType.DHCID:
			return DHCIDRecord.read(br);
		case RecordType.NSEC3:
			return NSEC3Record.read(br);
		case RecordType.NSEC3PARAM:
			return NSEC3PARAMRecord.read(br);
		case RecordType.TLSA:
			return TLSARecord.read(br);
		case RecordType.SMIMEA:
			return SMIMEARecord.read(br);
		case RecordType.HIP:
			return HIPRecord.read(br);
		case RecordType.NINFO:
			return NINFORecord.read(br);
		case RecordType.RKEY:
			return RKEYRecord.read(br);
		case RecordType.TALINK:
			return TALINKRecord.read(br);
		case RecordType.CDS:
			return CDSRecord.read(br);
		case RecordType.CDNSKEY:
			return CDNSKEYRecord.read(br);
		case RecordType.OPENPGPKEY:
			return OPENPGPKEYRecord.read(br);
		case RecordType.CSYNC:
			return CSYNCRecord.read(br);
		case RecordType.SPF:
			return SPFRecord.read(br);
		case RecordType.UINFO:
			return UINFORecord.read(br);
		case RecordType.UID:
			return UIDRecord.read(br);
		case RecordType.GID:
			return GIDRecord.read(br);
		case RecordType.UNSPEC:
			return UNSPECRecord.read(br);
		case RecordType.NID:
			return NIDRecord.read(br);
		case RecordType.L32:
			return L32Record.read(br);
		case RecordType.L64:
			return L64Record.read(br);
		case RecordType.LP:
			return LPRecord.read(br);
		case RecordType.EUI48:
			return EUI48Record.read(br);
		case RecordType.EUI64:
			return EUI64Record.read(br);
		case RecordType.TKEY:
			return TKEYRecord.read(br);
		case RecordType.TSIG:
			return TSIGRecord.read(br);
		case RecordType.URI:
			return URIRecord.read(br);
		case RecordType.CAA:
			return CAARecord.read(br);
		case RecordType.AVC:
			return AVCRecord.read(br);
		case RecordType.DOA:
			return DOARecord.read(br);
		case RecordType.TA:
			return TARecord.read(br);
		case RecordType.DLV:
			return DLVRecord.read(br);
		default:
			return UNKNOWNRecord.read(br);
	}
}

function decodeOption(code, data) {
	return readOption(code, bio.read(data));
}

function readOption(code, br): OptionData {
	assert((code & 0xffff) === code);

	switch (code) {
		case EOption.LLQ:
			return LLQOption.read(br);
		case EOption.UL:
			return ULOption.read(br);
		case EOption.NSID:
			return NSIDOption.read(br);
		case EOption.DAU:
			return DAUOption.read(br);
		case EOption.DHU:
			return DHUOption.read(br);
		case EOption.N3U:
			return N3UOption.read(br);
		case EOption.SUBNET:
			return SUBNETOption.read(br);
		case EOption.EXPIRE:
			return EXPIREOption.read(br);
		case EOption.COOKIE:
			return COOKIEOption.read(br);
		case EOption.TCPKEEPALIVE:
			return TCPKEEPALIVEOption.read(br);
		case EOption.PADDING:
			return PADDINGOption.read(br);
		case EOption.CHAIN:
			return CHAINOption.read(br);
		case EOption.KEYTAG:
			return KEYTAGOption.read(br);
		default:
			if (code >= EOption.LOCALSTART && code <= EOption.LOCALEND)
				return LOCALOption.read(br);
			return UNKNOWNOption.read(br);
	}
}

function fromZone(text: string, origin?, file?) {
	// assert(typeof text === 'string');
	const scan = lazy(require, './scan');
	return scan.parseZone(exports, text, origin, file);
}

function toZone(records) {
	assert(Array.isArray(records));

	let text = '';

	for (const rr of records) {
		assert(rr instanceof Record);
		text += rr.toString();
		text += '\n';
	}

	return text;
}

function truncate(msg, max) {
	assert(Buffer.isBuffer(msg));
	assert(msg.length >= 12);
	assert((max >>> 0) === max);
	assert(max >= 12);

	if (msg.length <= max)
		return msg;

	const br = bio.read(msg);

	br.seek(2);

	const bits = br.readU16BE();

	const counts = [
		br.readU16BE(),
		br.readU16BE(),
		br.readU16BE(),
		br.readU16BE()
	];

	let last = br.offset;

	for (let s = 0; s < 4; s++) {
		const count = counts[s];

		let i = 0;
		let j = 0;

		while (br.offset <= max) {
			last = br.offset;
			j = i;

			if (i === count)
				break;

			i += 1;

			readNameBR(br);

			// Question.
			if (s === 0) {
				br.seek(4);
				continue;
			}

			// Record.
			br.seek(8);
			br.seek(br.readU16BE());
		}

		counts[s] = j;
	}

	msg.writeUInt16BE(bits | Flag.TC, 2, true);
	msg.writeUInt16BE(counts[0], 4, true);
	msg.writeUInt16BE(counts[1], 6, true);
	msg.writeUInt16BE(counts[2], 8, true);
	msg.writeUInt16BE(counts[3], 10, true);

	return msg.slice(0, last);
}

/*
 * Expose
 */

export {Opcode}
export {Flag}
export {Code}
export {RecordType}
export {QuestionClass}
export {EFlag}
export {EOption}
export {KeyFlag}
export {EncAlg}
export {HashAlg}
export {algHashes}
export {NsecHash}
export {CertType}
export {DaneUsage}
export {DaneSelector}
export {DaneMatchingType}
export {SSHAlg}
export {SSHHash}
export {TSigAlg}
export {tsigAlgsByVal}
export {TKeyMode}

export {YEAR68}
export {LOC_EQUATOR}
export {LOC_PRIMEMERIDIAN}
export {LOC_HOURS}
export {LOC_DEGREES}
export {LOC_ALTITUDEBASE}

export {MAX_NAME_SIZE}
export {MAX_LABEL_SIZE}
export {MAX_UDP_SIZE}
export {STD_EDNS_SIZE}
export {MAX_EDNS_SIZE}
export {MAX_MSG_SIZE}
export {DNS_PORT}
export {DEFAULT_TTL}

export {opcodeToString}
export {stringToOpcode}
export {isOpcodeString}

export {codeToString}
export {stringToCode}
export {isCodeString}

export {typeToString}
export {stringToType}
export {isTypeString}

export {classToString}
export {stringToClass}
export {isClassString}

export {optionToString}
export {stringToOption}
export {isOptionString}

export {algToString}
export {stringToAlg}
export {isAlgString}

export {hashToString}
export {stringToHash}
export {isHashString}

export {Message}
export {EDNS}
export {Question}
export {Record}
export {RecordData}

export {UNKNOWNRecord}
export {ARecord}
export {NSRecord}
export {MDRecord}
export {MFRecord}
export {CNAMERecord}
export {SOARecord}
export {MBRecord}
export {MGRecord}
export {MRRecord}
export {NULLRecord}
export {WKSRecord}
export {PTRRecord}
export {HINFORecord}
export {MINFORecord}
export {MXRecord}
export {TXTRecord}
export {RPRecord}
export {AFSDBRecord}
export {X25Record}
export {ISDNRecord}
export {RTRecord}
export {NSAPRecord}
export {NSAPPTRRecord}
export {SIGRecord}
export {KEYRecord}
export {PXRecord}
export {GPOSRecord}
export {AAAARecord}
export {LOCRecord}
export {NXTRecord}
export {EIDRecord}
export {NIMLOCRecord}
export {SRVRecord}
export {ATMARecord}
export {NAPTRRecord}
export {KXRecord}
export {CERTRecord}
export {A6Record}
export {DNAMERecord}
export {OPTRecord}
export {APLRecord}
export {DSRecord}
export {SSHFPRecord}
export {IPSECKEYRecord}
export {RRSIGRecord}
export {NSECRecord}
export {DNSKEYRecord}
export {DHCIDRecord}
export {NSEC3Record}
export {NSEC3PARAMRecord}
export {TLSARecord}
export {SMIMEARecord}
export {HIPRecord}
export {NINFORecord}
export {RKEYRecord}
export {TALINKRecord}
export {CDSRecord}
export {CDNSKEYRecord}
export {OPENPGPKEYRecord}
export {CSYNCRecord}
export {SPFRecord}
export {UINFORecord}
export {UIDRecord}
export {GIDRecord}
export {UNSPECRecord}
export {NIDRecord}
export {L32Record}
export {L64Record}
export {LPRecord}
export {EUI48Record}
export {EUI64Record}
export {TKEYRecord}
export {TSIGRecord}
export {URIRecord}
export {CAARecord}
export {AVCRecord}
export {DOARecord}
export {TARecord}
export {DLVRecord}

export {Option}
export {OptionData}
export {UNKNOWNOption}
export {LLQOption}
export {ULOption}
export {NSIDOption}
export {DAUOption}
export {DHUOption}
export {N3UOption}
export {SUBNETOption}
export {EXPIREOption}
export {COOKIEOption}
export {TCPKEEPALIVEOption}
export {PADDINGOption}
export {CHAINOption}
export {KEYTAGOption}
export {LOCALOption}

export {AP}

export {records}
export {recordsByVal}
export {opts}
export {optsByVal}

export {decodeData}
export {readData}

export {decodeOption}
export {readOption}

export {fromZone}
export {toZone}
export {truncate}
