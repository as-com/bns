/*!
 * error.js - dns error for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import {Code, codeToString} from "./constants";

/**
 * DNS Error
 * @extends {Error}
 */
export default class DNSError extends Error {
	type: string;
	code: string;
	errno: Code;

	constructor(msg: string | number, code: Code = Code.SERVFAIL) {
		super();

		if (typeof msg === 'number') {
			code = msg;
			msg = '';
		}

		if (msg)
			msg = `: ${msg}.`;
		else
			msg = '';

		this.type = 'DNSError';
		this.name = 'DNSError';
		this.code = `E${codeToString(code)}`;
		this.errno = code;
		this.message = `${this.code}${msg}`;

		if (Error.captureStackTrace)
			Error.captureStackTrace(this, DNSError);
	}
}
