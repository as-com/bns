/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

let iana = null;
let scan = null;
let schema = null;

/*
 * Lazy Require
 */

export default function lazy(_require: typeof require, name: string) {
	// assert(typeof name === 'string');

	switch (name) {
		case './iana':
			if (!iana)
				iana = _require('./iana');
			return iana;
		case './scan':
			if (!scan)
				scan = _require('./scan');
			return scan;
		case './schema':
			if (!schema)
				schema = _require('./schema');
			return schema;
	}

	throw new Error(`Unknown module: ${name}.`);
}

