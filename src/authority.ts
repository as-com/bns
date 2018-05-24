/*!
 * authority.js - authority object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

import * as assert from "assert";
import {IServer} from "./server";

/**
 * Authority
 */

class Authority {
	zone: string;
	name: string;
	servers: IServer[];

	constructor(zone?: string, name?: string) {
		assert(zone == null || typeof zone === 'string');
		assert(name == null || typeof name === 'string');

		this.zone = zone || '.';
		this.name = name || '.';
		this.servers = [];
	}

	add(host, port) {
		assert(typeof host === 'string');
		assert((port & 0xffff) === port);
		this.servers.push({host, port});
		return this;
	}

	inject(auth) {
		assert(auth instanceof Authority);
		this.zone = auth.zone;
		this.name = auth.name;
		this.servers = auth.servers.slice();
		return this;
	}

	clone() {
		const copy = new Authority();
		return copy.inject(this);
	}
}

/*
 * Expose
 */

export default Authority;
