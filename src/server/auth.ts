/*!
 * auth.js - authoritative dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import DNSServer from "./dns";
import Zone from "../zone";
import DNSResolver from "../resolver/dns";
import {Message} from "../wire";

/**
 * AuthServer
 * @extends EventEmitter
 */

class AuthServer extends DNSServer<DNSResolver> {
	zone: Zone;
	file: string;
	ra: boolean;
    constructor(options) {
        super(options);
        this.zone = new Zone();
        this.file = null;
        this.ra = false;
        this.initOptions(options);
    }

	initOptions(options) {
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

/*
 * Expose
 */

export default AuthServer;
