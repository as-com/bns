/*!
 * lazy.ts - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import * as iana from "./iana";
import * as scan from "./scan";
import * as schema from "./schema";

/*
 * Lazy Require
 */

function lazy(_, name: string) {
	// assert(typeof name === 'string');

	switch (name) {
		case './iana':
			return iana;
		case './scan':
			return scan;
		case './schema':
			return schema;
	}

	throw new Error(`Unknown module: ${name}.`);
}

/*
 * Expose
 */

export default lazy;
