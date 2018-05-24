/*!
 * auth.js - authoritative dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import DNSServer, {IDNSServerOptions} from "./dns";
import Zone from "../zone";
import DNSResolver from "../resolver/dns";
import {Message} from "../wire";

export interface IAuthServerOptions extends IDNSServerOptions {

}

/**
 * AuthServer
 * @extends EventEmitter
 */
export default class AuthServer extends DNSServer<DNSResolver> {
	zone = new Zone();
	file: string | null = null;
	ra = false;

	constructor(options?: IAuthServerOptions) {
		super(options);

		this.initOptions(options);
	}

	initOptions(options?: IAuthServerOptions) {
		return super.initOptions(options);
	}

	setOrigin(name) {
		this.zone.setOrigin(name);
		return this;
	}

	setFile(file) {
		this.zone.clearRecords();
		this.zone.fromFile(file);
		this.file = file;
		return this;
	}

	async resolve(req, rinfo): Promise<Message> {
		const [qs] = req.question;
		const {name, type} = qs;
		return this.zone.resolve(name, type);
	}
}
