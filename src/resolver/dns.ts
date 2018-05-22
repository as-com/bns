/*!
 * resolver.js - dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import * as assert from "assert";
import * as EventEmitter from "events";
import IP from "binet";
import {DNS_PORT, MAX_EDNS_SIZE, MAX_UDP_SIZE} from "../constants";
import * as encoding from "../encoding";
import {Client} from "../net";

import * as util from "../util";
import {Code, Message, Opcode, Question, RecordType} from "../wire";
import {IServer} from "../server";
import Timer = NodeJS.Timer;

/**
 * DNSResolver
 * @extends EventEmitter
 */

class DNSResolver extends EventEmitter {
	socket: Client;
	pending: Map<number, Query>;
	timer: Timer;
	inet6: boolean;
	tcp: boolean;
	forceTCP: boolean;
	maxAttempts: number;
	maxTimeout: number;
	rd: boolean;
	edns: boolean;
	ednsSize: number;
	dnssec: boolean;

    constructor(options) {
        super();

        this.socket = new Client(options);
        this.pending = new Map();
        this.timer = null;

        this.inet6 = this.socket.inet6;
        this.tcp = this.socket.tcp;
        this.forceTCP = false;
        this.maxAttempts = 3;
        this.maxTimeout = 2000;
        this.rd = false;
        this.edns = false;
        this.ednsSize = MAX_EDNS_SIZE;
        this.dnssec = false;

        this.init();
    }

    init() {
        this.on('error', () => {
        });

        this.socket.on('close', () => {
            this.emit('close');
        });

        this.socket.on('error', (err) => {
            this.emit('error', err);
        });

        this.socket.on('listening', () => {
            this.emit('listening');
        });

        this.socket.on('message', (msg, rinfo) => {
            try {
                this.handle(msg, rinfo);
            } catch (e) {
                this.emit('error', e);
            }
        });
    }

    parseOptions(options) {
        if (options == null)
            return this;

        assert(options && typeof options === 'object');

        if (options.forceTCP != null) {
            assert(typeof options.forceTCP === 'boolean');
            this.forceTCP = options.forceTCP;
        }

        if (options.maxAttempts != null) {
            assert((options.maxAttempts >>> 0) === options.maxAttempts);
            this.maxAttempts = options.maxAttempts;
        }

        if (options.maxTimeout != null) {
            assert((options.maxTimeout >>> 0) === options.maxTimeout);
            this.maxTimeout = options.maxTimeout;
        }

        if (options.edns != null) {
            assert(typeof options.edns === 'boolean');
            this.edns = options.edns;
        }

        if (options.ednsSize != null) {
            assert((options.ednsSize >>> 0) === options.ednsSize);
            assert(options.ednsSize >= MAX_UDP_SIZE);
            assert(options.ednsSize <= MAX_EDNS_SIZE);
            this.ednsSize = options.ednsSize;
        }

        if (options.dnssec != null) {
            assert(typeof options.dnssec === 'boolean');
            this.dnssec = options.dnssec;
            if (this.dnssec)
                this.edns = true;
        }

        return this;
    }

    initOptions(options) {
        return this.parseOptions(options);
    }

    log(...args) {
        this.emit('log', ...args);
    }

    async open(...args) {
        await this.socket.bind(...args);

        if (this.edns) {
            this.socket.setRecvBufferSize(this.ednsSize);
            this.socket.setSendBufferSize(this.ednsSize);
        } else {
            this.socket.setRecvBufferSize(MAX_UDP_SIZE);
            this.socket.setSendBufferSize(MAX_UDP_SIZE);
        }

        this.timer = setInterval(() => this.maybeRetry(), 1000);
        this.timer.unref();

        return this;
    }

    async close() {
        await this.socket.close();

        if (this.timer != null) {
            clearInterval(this.timer);
            this.timer = null;
        }

        this.cancel();

        return this;
    }

    cancel() {
        const pending = this.pending;

        this.pending = new Map();

        for (const query of pending.values()) {
            query.unref();
            try {
                query.reject(new Error('Request cancelled.'));
            } catch (e) {
                this.emit('error', e);
            }
        }

        return this;
    }

    async bind(...args) {
        return this.open(...args);
    }

    maybeRetry() {
        const now = Date.now();

        for (const query of this.pending.values()) {
            if (now > query.time + this.maxTimeout)
                this.retry(query, true, false);
        }
    }

    verify(msg, host, port) {
        return true;
    }

    useTCP(type, size) {
        if (this.forceTCP) {
            assert(this.tcp);
            return true;
        }

        if (!this.tcp)
            return false;

        // Dig-style.
        if (this.rd) {
			if (type === RecordType.ANY)
                return true;
        }

        if (this.edns)
            return size > this.ednsSize;

        return size > MAX_UDP_SIZE;
    }

    retry(query, rotate, forceTCP) {
        let server = query.server;

        query.unref();

        // Make sure our socket is dead.
        if (server.tcp) {
            const {port, host} = server;
            this.socket.kill(port, host);
        }

        if (query.attempts >= this.maxAttempts) {
            this.pending.delete(query.id);

            if (query.res)
                query.resolve(query.res);
            else
                query.reject(new Error('Request timed out.'));

            return;
        }

        if (rotate) {
            server = query.nextServer(server.tcp);
            this.log('Switched servers to: %s (%d).', server.host, query.id);
        }

        if (this.tcp && forceTCP)
            server.tcp = true;

        const {port, host, tcp} = server;
        const msg = query.req.encode();

        // Retry over TCP or UDP.
        this.socket.send(msg, 0, msg.length, port, host, tcp);

        this.log('Retrying (%s): %d (tcp=%s)...', host, query.id, tcp);

        // Update time.
        query.ref();
        query.time = Date.now();
        query.attempts += 1;
    }

    handle(msg, rinfo) {
        // Close socket once we get an answer.
        if (rinfo.tcp) {
            const {port, address} = rinfo;
            this.socket.drop(port, address);
        }

        if (msg.length < 2) {
            this.log('Malformed message (%s).', rinfo.address);
            return;
        }

        const id = msg.readUInt16BE(0, true);
        const query = this.pending.get(id);

        if (!query) {
            this.log('Unsolicited message (%s): %d.', rinfo.address, id);
            return;
        }

        const {host, port} = query.server;

        if (rinfo.address !== host || port !== rinfo.port) {
            this.log(
                'Possible reflection attack (%s != %s): %d.',
                rinfo.address, host, id);
            return;
        }

        query.unref();

        let {req} = query;
        let res = null;

        try {
            res = Message.decode(msg);
        } catch (e) {
            this.log('Message %d failed deserialization (%s):', id, rinfo.address);
            this.log(e.stack);
            this.pending.delete(id);
            query.reject(new Error('Encoding error.'));
            return;
        }

        if (!res.qr) {
            this.pending.delete(id);
            query.reject(new Error('Not a response.'));
            return;
        }

        if (!sameQuestion(req, res)) {
            this.pending.delete(id);
            query.reject(new Error('Invalid question.'));
            return;
        }

        if (this.tcp && res.tc) {
            if (rinfo.tcp) {
                this.pending.delete(id);
                query.reject(new Error('Truncated TCP msg.'));
                return;
            }

            // Retry over TCP if truncated.
            this.log('Retrying over TCP (%s): %d.', host, id);
            this.retry(query, false, true);

            return;
        }

		if (res.opcode !== Opcode.QUERY) {
            this.pending.delete(id);
            query.reject(new Error('Unexpected opcode.'));
            return;
        }

		if ((res.code === Code.FORMERR
			|| res.code === Code.NOTIMP
			|| res.code === Code.SERVFAIL)
            && (!res.isEDNS() && req.isEDNS())) {
            // They don't like edns.
            req = req.clone();
            req.unsetEDNS();

            query.req = req;
            query.res = res;

            this.log('Retrying without EDNS (%s): %d.', host, id);
            this.retry(query, false, false);

            return;
        }

		if (res.code === Code.FORMERR) {
            this.pending.delete(id);
            query.reject(new Error('Format error.'));
            return;
        }

		if (res.code === Code.SERVFAIL) {
            query.res = res;
            this.log('Retrying due to failure (%s): %d.', host, id);
            this.retry(query, true, false);
            return;
        }

        if (isLame(req, res)) {
            this.pending.delete(id);
            query.reject(new Error('Server is lame.'));
            return;
        }

        if (!this.verify(msg, host, port)) {
            this.pending.delete(id);
            query.reject(new Error('Could not verify response.'));
            return;
        }

        this.pending.delete(id);

        query.resolve(res);
    }

	async exchange(req, servers: IServer[]) {
        assert(req instanceof Message);
        assert(Array.isArray(servers));
        assert(req.question.length > 0);

        const [qs] = req.question;

        if (!util.isName(qs.name))
            throw new Error('Invalid qname.');

        if (servers.length === 0)
            throw new Error('No servers available.');

        req.id = util.id();
        req.qr = false;

        const msg = req.encode();
        const tcp = this.useTCP(qs.type, msg.length);
        const query = new Query(req, servers, tcp);
        const {port, host} = query.server;

        this.log('Querying server: %s (%d) (tcp=%s)', host, req.id, tcp);

        this.socket.send(msg, 0, msg.length, port, host, tcp);
        this.pending.set(query.id, query);

        query.ref();

        return new Promise((resolve, reject) => {
            query.resolve = resolve;
            query.reject = reject;
        });
    }

	async query(qs, servers: IServer[]) {
        assert(qs instanceof Question);
        assert(Array.isArray(servers));

        const req = new Message();
		req.opcode = Opcode.QUERY;
        req.rd = this.rd;
        req.question.push(qs);

        if (this.edns) {
            req.setEDNS(this.ednsSize, this.dnssec);

            // Cookie for recursive queries.
            // Note that some authoritative
            // servers get mad at this, most
            // notably alidns' servers.
            if (this.rd)
                req.edns.setCookie(util.cookie());
        }

        if (this.rd)
            req.ad = true;

        return this.exchange(req, servers);
    }

    async lookup(name, type, servers) {
        const qs = new Question(name, type);
        return this.query(qs, servers);
    }

    async reverse(addr, servers) {
        const name = encoding.reverse(addr);
		return this.lookup(name, RecordType.PTR, servers);
    }
}

/**
 * Query
 */

export class Query {
	id: number;
	req: Message;
	index: number;
	servers: IServer[];
	resolve: Function;
	reject: Function;
	attempts: number;
	res: null;
	server: any; // TODO
	time: number;
	timer: Timer;

	constructor(req: Message, servers: IServer[], tcp) {
		// assert(req instanceof Message);
		// assert(Array.isArray(servers));
        assert(servers.length > 0);
        assert(typeof tcp === 'boolean');

        this.id = req.id;
        this.req = req;
        this.index = 0;
        this.servers = util.sortRandom(servers);
        this.resolve = null;
        this.reject = null;
        this.attempts = 1;
        this.res = null;
        this.server = null;
        this.time = Date.now();
        this.timer = null;

        this.nextServer(tcp);
    }

    ref() {
        if (this.timer == null)
            this.timer = setInterval(noop, 0x7fffffff);
    }

    unref() {
        if (this.timer != null)
            clearInterval(this.timer);
        this.timer = null;
    }

    getServer(index, tcp) {
        assert((index >>> 0) < this.servers.length);
        assert(typeof tcp === 'boolean');

        const server = this.servers[index];

        let addr;

        if (typeof addr === 'string') {
            addr = IP.fromHost(server, DNS_PORT);
        } else {
            if (!server || typeof server !== 'object')
                throw new Error('Bad address passed to query.');
            addr = server;
        }

        const host = addr.address || addr.host;
        const port = addr.port || DNS_PORT;

        if (!util.isIP(host))
            throw new Error('Bad address passed to query.');

        if ((port & 0xffff) !== port)
            throw new Error('Bad address passed to query.');

        return {
            host: IP.normalize(host),
            port,
            tcp
        };
    }

    nextServer(tcp) {
        assert(this.index < this.servers.length);

        this.index += 1;

        if (this.index === this.servers.length)
            this.index = 0;

        this.server = this.getServer(this.index, tcp);

        return this.server;
    }
}

/*
 * Helpers
 */

function sameQuestion(req, res) {
    switch (res.code) {
		case Code.NOTIMP:
		case Code.FORMERR:
		case Code.NXRRSET:
            if (res.question.length === 0)
                break;
		case Code.BADCOOKIE:
		case Code.NOERROR:
		case Code.NXDOMAIN:
		case Code.YXDOMAIN:
		case Code.REFUSED:
		case Code.SERVFAIL:
        default:
            if (res.question.length === 0) {
                if (res.tc)
                    return true;
                return false;
            }

            if (res.question.length > 1)
                return false;

            if (!res.question[0].equals(req.question[0]))
                return false;

            break;
    }

    return true;
}

function isLame(req, res) {
    if (req.question.length === 0)
        return true;

    const name = req.question[0].name;

	if (res.code !== Code.NOERROR
		&& res.code !== Code.YXDOMAIN
		&& res.code !== Code.NXDOMAIN) {
        return false;
    }

    if (res.answer.length !== 0)
        return false;

    for (const rr of res.authority) {
		if (rr.type !== RecordType.NS)
            continue;

        if (util.equal(rr.name, name))
            continue;

        if (util.isSubdomain(rr.name, name))
            continue;

        return true;
    }

    return false;
}

function noop() {
}

/*
 * Expose
 */

export default DNSResolver;
