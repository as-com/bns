/*!
 * hosts.js - hosts file for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import * as assert from "assert";
import * as Path from "path";
import * as fs from "bfile";
import * as IP from "binet";
import * as encoding from "./encoding";
import {AAAARecord, ARecord, PTRRecord, QuestionClass, Record, RecordType} from "./wire";
import * as util from "./util";

/**
 * Hosts
 */

class Hosts {
	map: Map<string, HostEntry>;
	rev: Map<string, string>;

    constructor() {
        this.map = new Map();
        this.rev = new Map();
    }

	inject(hosts: Hosts) {
		// assert(hosts instanceof this.constructor);

        this.map.clear();

        for (const [key, value] of hosts.map)
            this.map.set(key, value.clone());

        this.rev.clear();

        for (const [key, value] of hosts.rev)
            this.rev.set(key, value);

        return this;
    }

    clone() {
		const copy = new Hosts();
        return copy.inject(this);
    }

    clear() {
        this.clearHosts();
        return this;
    }

    getSystem() {
        if (process.platform === 'win32') {
            const root = process.env.SystemRoot || 'C:\\Windows';
            return Path.join(root, '\\System32\\Drivers\\etc\\hosts');
        }

        return '/etc/hosts';
    }

    getHosts() {
        const out = [];

        for (const [name, addr] of this.map) {
            if (addr.inet4)
                out.push([name, addr.inet4]);

            if (addr.inet6)
                out.push([name, addr.inet6]);
        }

        return out;
    }

    setHosts(hosts) {
        assert(Array.isArray(hosts));

        this.clearHosts();

        for (const item of hosts) {
            assert(Array.isArray(item) && item.length === 2);
            const [name, addr] = item;
            this.addHost(name, addr);
        }

        return this;
    }

    clearHosts() {
        this.map.clear();
        this.rev.clear();
        return this;
    }

    setDefault() {
        return this.setLocal();
    }

    setLocal() {
        this.clearHosts();
        this.addHost('localhost', '127.0.0.1');
        this.addHost('localhost', '::1');
        return this;
    }

	addHost(name: string, host: string, hostname: string = null) {
		// assert(typeof name === 'string');
		// assert(typeof host === 'string');
		// assert(hostname === null || typeof hostname === 'string');

        name = name.toLowerCase();
        name = util.fqdn(name);

        if (!util.isName(name))
            throw new Error('Invalid name.');

        let local = false;

        if (util.endsWith(name, '.localdomain.')) {
            name = name.slice(0, -12);
            local = true;
        }

        if (hostname) {
            hostname = hostname.toLowerCase();
            hostname = util.fqdn(hostname);

            if (!util.isName(hostname))
                throw new Error('Invalid hostname.');
        }

        let entry = this.map.get(name);

        if (!entry)
            entry = new HostEntry();

        const ip = IP.toBuffer(host);
        const addr = IP.toString(ip);
        const rev = encoding.reverse(addr);

        entry.name = name;

        if (IP.isIPv4(ip))
            entry.inet4 = addr;
        else
            entry.inet6 = addr;

        entry.hostname = hostname;
        entry.local = local;

        this.map.set(name, entry);
        this.rev.set(rev, name);

        return this;
    }

    lookup(name) {
        const key = name.toLowerCase();
        const ptr = this.rev.get(key);

        if (ptr)
            return this.map.get(ptr);

        return this.map.get(key);
    }

	query(name: string, type: number) {
		// assert(typeof name === 'string');
		// assert((type & 0xffff) === type);

        const entry = this.lookup(name);

        if (!entry)
            return null;

        const answer = [];

		if (type === RecordType.PTR) {
            const rr = new Record();
            const rd = new PTRRecord();
            rr.name = name;
			rr.class = QuestionClass.IN;
            rr.ttl = 10800;
			rr.type = RecordType.PTR;
            rr.data = rd;
            rd.ptr = entry.name;
            answer.push(rr);
            return answer;
        }

		if (type === RecordType.A || type === RecordType.ANY) {
            if (entry.inet4) {
                const rr = new Record();
                const rd = new ARecord();
                rr.name = name;
				rr.class = QuestionClass.IN;
                rr.ttl = 10800;
				rr.type = RecordType.A;
                rr.data = rd;
                rd.address = entry.inet4;
                answer.push(rr);
            }
        }

		if (type === RecordType.AAAA || type === RecordType.ANY) {
            if (entry.inet6) {
                const rr = new Record();
                const rd = new AAAARecord();
                rr.name = name;
				rr.class = QuestionClass.IN;
                rr.ttl = 10800;
				rr.type = RecordType.AAAA;
                rr.data = rd;
                rd.address = entry.inet6;
                answer.push(rr);
            }
        }

        return answer;
    }

    toString() {
        let out = '';

        out += '#\n';
        out += '# /etc/hosts: static lookup table for host names\n';
        out += '# (generated by bns)\n';
        out += '#\n';
        out += '\n';
        out += '# <ip-address> <hostname.domain.org> <hostname>\n';

        for (const entry of this.map.values())
            out += entry.toString();

        out += '\n';
        out += '# End of file\n';

        return out;
    }

    fromString(text) {
        assert(typeof text === 'string');

        text = text.toLowerCase();

        const lines = util.splitLines(text, true);

        for (const chunk of lines) {
            const line = stripComments(chunk);

            if (line.length === 0)
                continue;

            const parts = util.splitSP(line);
            const ip = parts[0];

            let hostname = null;

            if (parts.length > 2)
                hostname = parts.pop();

            for (let i = 1; i < parts.length; i++) {
                const name = parts[i];
                try {
                    this.addHost(name, ip, hostname);
                } catch (e) {
                    continue;
                }
            }
        }

        return this;
    }

    static fromString(text) {
        return new this().fromString(text);
    }

    fromFile(file) {
        assert(typeof file === 'string');
        const text = fs.readFileSync(file, 'utf8');
        return this.fromString(text);
    }

    static fromFile(file) {
        return new this().fromFile(file);
    }

    fromSystem() {
        const file = this.getSystem();
        try {
            return this.fromFile(file);
        } catch (e) {
            return this.setLocal();
        }
    }

    static fromSystem() {
        return new this().fromSystem();
    }

    async fromFileAsync(file) {
        assert(typeof file === 'string');
        const text = await fs.readFile(file, 'utf8');
        return this.fromString(text);
    }

    static fromFileAsync(file) {
        return new this().fromFileAsync(file);
    }

    async fromSystemAsync() {
        const file = this.getSystem();
        try {
            return await this.fromFileAsync(file);
        } catch (e) {
            return this.setLocal();
        }
    }

    static fromSystemAsync() {
        return new this().fromSystemAsync();
    }
}

/**
 * HostEntry
 */

export class HostEntry {
	name: string;
	inet4: string;
	inet6: string;
	hostname: string;
	local: boolean;

    constructor() {
        this.name = 'localhost';
        this.inet4 = null;
        this.inet6 = null;
        this.hostname = null;
        this.local = true;
    }

	inject(entry: HostEntry) {
		// assert(entry instanceof this.constructor);
        this.name = entry.name;
        this.inet4 = entry.inet4;
        this.inet6 = entry.inet6;
        this.hostname = entry.hostname;
        this.local = entry.local;
        return this;
    }

    clone() {
		const copy = new HostEntry();
        return copy.inject(this);
    }

    toString() {
        let out = '';

        let name = util.trimFQDN(this.name);
        let hostname = '';

        if (this.local)
            name += '.localdomain';

        if (this.hostname)
            hostname = ` ${util.trimFQDN(this.hostname)}`;

        if (this.inet4)
            out += `${this.inet4} ${name}${hostname}\n`;

        if (this.inet6)
            out += `${this.inet6} ${name}${hostname}\n`;

        return out;
    }
}

/*
 * Helpers
 */

function stripComments(str) {
    assert(typeof str === 'string');
    return str.replace(/[ \t\v]*#.*$/g, '');
}

/*
 * Expose
 */

export default Hosts;
