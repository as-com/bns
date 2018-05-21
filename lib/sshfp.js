/*!
 * sshfp.js - SSHFP for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import assert from "assert";
import {classes, sshAlgs, sshAlgsByVal, sshHashes, sshHashesByVal, types} from "./constants";
import * as crypto from "./crypto";
import * as util from "./util";
import {Record, SSHFPRecord} from "./wire";

/*
 * SSHFP
 */

const sshfp = exports;

sshfp.hash = function hash(key, digestType) {
  assert(Buffer.isBuffer(key));
  assert((digestType & 0xff) === digestType);

  switch (digestType) {
    case sshHashes.SHA1:
      return crypto.sha1.digest(key);
    case sshHashes.SHA256:
      return crypto.sha256.digest(key);
  }

  return null;
};

sshfp.validate = function validate(key, digestType, fingerprint) {
  assert(Buffer.isBuffer(fingerprint));

  const hash = sshfp.hash(key, digestType);

  if (!hash)
    return false;

  return hash.equals(fingerprint);
};

sshfp.create = function create(key, name, alg, digest) {
  assert(Buffer.isBuffer(key));

  assert((alg & 0xff) === alg);
  assert((digest & 0xff) === digest);

  const rr = new Record();
  const rd = new SSHFPRecord();

  rr.name = util.fqdn(name);
  rr.type = types.SSHFP;
  rr.class = classes.IN;
  rr.ttl = 0;
  rr.data = rd;
  rd.algorithm = alg;
  rd.digestType = digest;

  return sshfp.sign(rr, key);
};

sshfp.sign = function sign(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.SSHFP);

  const rd = rr.data;
  const hash = sshfp.hash(key, rd.digestType);

  if (!hash)
    throw new Error('Unknown digest type.');

  rd.fingerprint = hash;

  return rr;
};

sshfp.verify = function verify(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.SSHFP);

  const rd = rr.data;

  return sshfp.validate(key, rd.digestType, rd.fingerprint);
};

/*
 * Expose
 */

sshfp.algs = sshAlgs;
sshfp.algsByVal = sshAlgsByVal;
sshfp.hashes = sshHashes;
sshfp.hashesByVal = sshHashesByVal;
