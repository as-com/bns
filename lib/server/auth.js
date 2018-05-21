/*!
 * auth.js - authoritative dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import DNSServer from "./dns";
import Zone from "../zone";

/**
 * AuthServer
 * @extends EventEmitter
 */

class AuthServer extends DNSServer {
  constructor(options) {
    super(options);
    this.zone = new Zone();
    this.file = null;
    this.ra = false;
    this.initOptions(options);
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

  async resolve(req, rinfo) {
    const [qs] = req.question;
    const {name, type} = qs;
    return this.zone.resolve(name, type);
  }
}

/*
 * Expose
 */

export default AuthServer;
