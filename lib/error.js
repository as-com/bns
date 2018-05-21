/*!
 * error.js - dns error for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import {codes, codeToString} from "./constants";

/**
 * DNS Error
 * @extends {Error}
 */

class DNSError extends Error {
  constructor(msg, code) {
    super();

    if (typeof msg === 'number') {
      code = msg;
      msg = '';
    }

    if (code == null)
      code = codes.SERVFAIL;

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

/*
 * Expose
 */

export default DNSError;
