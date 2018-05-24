/*!
 * stub.ts - stub dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import DNSServer, {IDNSServerOptions} from "./dns";
import StubResolver, {IStubResolverOptions} from "../resolver/stub";
import Hosts from "../hosts";
import ResolvConf from "../resolvconf";

export interface IStubServerOptions extends IDNSServerOptions, IStubResolverOptions {

}

/**
 * StubServer
 * @extends EventEmitter
 */
export default class StubServer extends DNSServer<StubResolver> {
	constructor(options?: IStubServerOptions) {
		super(options);
		this.resolver = new StubResolver(options);
		this.resolver.on('log', (...args) => this.emit('log', ...args));
		this.resolver.on('error', err => this.emit('error', err));
		this.ra = true;
		this.initOptions(options);
	}

	getServers() {
		return this.resolver.getServers();
	}

	setServers(servers) {
		this.resolver.setServers(servers);
		return this;
	}

	get conf(): ResolvConf {
		return this.resolver.conf;
	}

	set conf(value) {
		this.resolver.conf = value;
	}

	get hosts(): Hosts {
		return this.resolver.hosts;
	}

	set hosts(value) {
		this.resolver.hosts = value;
	}
}
