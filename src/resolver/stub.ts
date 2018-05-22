/*!
 * stub.ts - stub dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import * as assert from "assert";
import {MAX_EDNS_SIZE} from "../constants";
import DNSResolver from "./dns";
import * as encoding from "../encoding";
import Hosts from "../hosts";
import ResolvConf from "../resolvconf";
import * as util from "../util";
import {Code, Message, Opcode, Question, RecordType} from "../wire";

/**
 * StubResolver
 * @extends DNSResolver
 */

class StubResolver extends DNSResolver {
	conf: ResolvConf;
	hosts: Hosts;
	constructor(options) {
		super(options);

		this.rd = true;
		this.conf = new ResolvConf();
		this.hosts = new Hosts();

		this.initOptions(options);
	}

	initOptions(options) {
		if (options == null)
			return this;

		this.parseOptions(options);

		if (options.conf != null) {
			assert(options.conf instanceof ResolvConf);
			this.conf = options.conf;
		}

		if (options.hosts != null) {
			assert(options.hosts instanceof Hosts);
			this.hosts = options.hosts;
		}

		if (options.rd != null) {
			assert(typeof options.rd === 'boolean');
			this.rd = options.rd;
		}

		return this;
	}

	getRaw() {
		return this.conf.getRaw(this.inet6);
	}

	getServers() {
		return this.conf.getServers();
	}

	setServers(servers) {
		this.conf.setServers(servers);
		return this;
	}

	getHosts() {
		return this.hosts.getHosts();
	}

	setHosts(hosts) {
		this.hosts.setHosts(hosts);
		return this;
	}

	async resolve(qs: Question) {
		// assert(qs instanceof Question);

		const {name, type} = qs;
		const answer = this.hosts.query(name, type);

		if (answer) {
			const res = new Message();

			res.id = util.id();
			res.opcode = Opcode.QUERY;
			res.code = Code.NOERROR;
			res.qr = true;
			res.rd = true;
			res.ra = true;
			res.ad = true;
			res.question = [qs];
			res.answer = answer;

			if (this.edns)
				res.setEDNS(MAX_EDNS_SIZE, this.dnssec);

			return res;
		}

		return this.query(qs, this.getRaw());
	}

	async lookup(name, type) {
		const qs = new Question(name, type);
		return this.resolve(qs);
	}

	async reverse(addr) {
		const name = encoding.reverse(addr);
		return this.lookup(name, RecordType.PTR);
	}
}

/*
 * Expose
 */

export default StubResolver;
