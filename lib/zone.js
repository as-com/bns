/*!
 * hints.js - root hints object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

import assert from "assert";
import fs from "bfile";
import {codes, types} from "./constants";
import * as util from "./util";
import {Message, Record} from "./wire";
/*
 * Constants
 */
import ROOT_HINTS from "./roothints";

/*
 * Cache
 */

let hints = null;

/**
 * Zone
 */

class Zone {
  constructor(origin) {
    this.origin = '.';
    this.count = 0;
    this.names = new Map();
    this.wild = new RecordMap();
    this.nsec = new NameList();
    this.setOrigin(origin);
  }

  clear() {
    this.origin = '.';
    this.count = 0;
    this.clearRecords();
    return this;
  }

  clearRecords() {
    this.names.clear();
    this.wild.clear();
    this.nsec.clear();
    return this;
  }

  setOrigin(origin) {
    if (origin == null)
      origin = '.';

    assert(util.isFQDN(origin));

    this.origin = origin.toLowerCase();
    this.count = util.countLabels(this.origin);

    return this;
  }

  insert(record) {
    assert(record instanceof Record);

    const rr = record.deepClone();

    // Lowercase.
    rr.canonical();

    if (rr.type !== types.A && rr.type !== types.AAAA) {
      if (!util.isSubdomain(this.origin, rr.name))
        throw new Error('Not a child of this zone.');
    }

    if (isWild(rr.name)) {
      this.wild.insert(rr);
    } else {
      if (!this.names.has(rr.name))
        this.names.set(rr.name, new RecordMap());

      const map = this.names.get(rr.name);

      map.insert(rr);
    }

    switch (rr.type) {
      case types.NSEC: {
        this.nsec.insert(rr.name);
        break;
      }
    }

    return this;
  }

  push(name, type, an) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);
    assert(Array.isArray(an));

    const map = this.names.get(name);

    if (map)
      map.push(name, type, an);

    this.wild.push(name, type, an);

    return this;
  }

  get(name, type) {
    const an = [];
    this.push(name, type, an);
    return an;
  }

  glue(name, an) {
    assert(util.isFQDN(name));
    assert(Array.isArray(an));

    this.push(name, types.A, an);
    this.push(name, types.AAAA, an);

    return this;
  }

  find(name, type) {
    const an = this.get(name, type);
    const ar = [];

    for (const rr of an) {
      switch (rr.type) {
        case types.CNAME:
          this.glue(rr.data.target, an);
          break;
        case types.DNAME:
          this.glue(rr.data.target, an);
          break;
        case types.NS:
          this.glue(rr.data.ns, ar);
          break;
        case types.SOA:
          this.glue(rr.data.ns, ar);
          break;
        case types.MX:
          this.glue(rr.data.mx, ar);
          break;
        case types.SRV:
          this.glue(rr.data.target, ar);
          break;
      }
    }

    return [an, ar];
  }

  getHints() {
    if (!hints) {
      hints = wire.fromZone(ROOT_HINTS, '.');
      for (const rr of hints)
        rr.canonical();
    }

    const ns = [];
    const ar = [];

    for (const rr of hints) {
      switch (rr.type) {
        case types.NS:
          ns.push(rr);
          break;
        case types.A:
        case types.AAAA:
          ar.push(rr);
          break;
      }
    }

    return [ns, ar];
  }

  proveNoData(ns) {
    this.push(this.origin, types.NSEC, true, ns);
    return this;
  }

  proveNameError(name, ns) {
    const lower = this.nsec.lower(name);

    if (lower)
      this.push(lower, types.NSEC, true, ns);

    this.proveNoData(ns);

    return this;
  }

  query(name, type) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);

    const [an, ar] = this.find(name, type);

    if (an.length > 0) {
      const aa = util.equal(name, this.origin);
      return [an, [], ar, aa, true];
    }

    const labels = util.split(name);

    if (this.origin !== '.') {
      const zone = util.from(name, labels, -this.count);

      // Refer them back to the root zone.
      if (this.origin !== zone) {
        const [ns, ar] = this.getHints();
        return [[], ns, ar, false, true];
      }
    }

    // Serve an SoA (no data).
    if (labels.length === this.count) {
      const ns = this.get(this.origin, types.SOA);
      this.proveNoData(ns);
      return [[], ns, [], true, false];
    }

    const index = this.count + 1;
    const child = util.from(name, labels, -index);
    const [ns, glue] = this.find(child, types.NS);

    // Serve an SoA (nxdomain).
    if (ns.length === 0) {
      const ns = this.get(this.origin, types.SOA);
      this.proveNameError(child, ns);
      return [[], ns, [], false, false];
    }

    this.push(child, types.DS, ns);

    return [[], ns, glue, false, true];
  }

  resolve(name, type) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);

    const qname = name.toLowerCase();
    const qtype = type === types.ANY ? types.NS : type;
    const [an, ns, ar, aa, ok] = this.query(qname, qtype);
    const msg = new Message();

    if (!aa && !ok)
      msg.code = codes.NXDOMAIN;

    msg.aa = aa;
    msg.answer = an;
    msg.authority = ns;
    msg.additional = ar;

    return msg;
  }

  fromString(text, file) {
    const rrs = wire.fromZone(text, this.origin, file);

    for (const rr of rrs)
      this.insert(rr);

    return this;
  }

  static fromString(origin, text, file) {
    return new this(origin).fromString(text, file);
  }

  fromFile(file) {
    const text = fs.readFileSync(file, 'utf8');
    return this.fromString(text, file);
  }

  static fromFile(origin, file) {
    return new this(origin).fromFile(file);
  }
}

/**
 * RecordMap
 */

class RecordMap {
  constructor() {
    // type -> rrs
    this.rrs = new Map();
    // type covered -> sigs
    this.sigs = new Map();
  }

  clear() {
    this.rrs.clear();
    this.sigs.clear();
    return this;
  }

  insert(rr) {
    assert(rr instanceof Record);

    if (!this.rrs.has(rr.type))
      this.rrs.set(rr.type, []);

    const rrs = this.rrs.get(rr.type);

    rrs.push(rr);

    switch (rr.type) {
      case types.RRSIG: {
        const {typeCovered} = rr.data;

        if (!this.sigs.has(typeCovered))
          this.sigs.set(typeCovered, []);

        const sigs = this.sigs.get(typeCovered);
        sigs.push(rr);

        break;
      }
    }

    return this;
  }

  push(name, type, an) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);
    assert(Array.isArray(an));

    const rrs = this.rrs.get(type);

    if (!rrs || rrs.length === 0)
      return this;

    for (const rr of rrs)
      an.push(convert(name, rr));

    const sigs = this.sigs.get(type);

    if (sigs) {
      for (const rr of sigs)
        an.push(convert(name, rr));
    }

    return this;
  }

  get(name, type) {
    const an = [];
    this.push(name, type, an);
    return an;
  }
}

/**
 * NameList
 */

class NameList {
  constructor() {
    this.names = [];
  }

  clear() {
    this.names.length = 0;
    return this;
  }

  insert(name) {
    return insertString(this.names, name);
  }

  lower(name) {
    return findLower(this.names, name);
  }
}

/*
 * Helpers
 */

function search(items, key, compare, insert) {
  let start = 0;
  let end = items.length - 1;

  while (start <= end) {
    const pos = (start + end) >>> 1;
    const cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start;
}

function insert(items, item, compare, uniq) {
  const i = search(items, item, compare, true);

  if (uniq && i < items.length) {
    if (compare(items[i], item) === 0)
      return -1;
  }

  if (i === 0)
    items.unshift(item);
  else if (i === items.length)
    items.push(item);
  else
    items.splice(i, 0, item);

  return i;
}

function insertString(items, name) {
  assert(Array.isArray(items));
  assert(typeof name === 'string');

  return insert(items, name, util.compare, true) !== -1;
}

function findLower(items, name) {
  assert(Array.isArray(items));
  assert(typeof name === 'string');

  if (items.length === 0)
    return null;

  const i = search(items, name, util.compare, true);
  const match = items[i];
  const cmp = util.compare(match, name);

  if (cmp === 0)
    throw new Error('Not an NXDOMAIN.');

  if (cmp < 0)
    return match;

  if (i === 0)
    return null;

  return items[i - 1];
}

function isWild(name) {
  assert(typeof name === 'string');
  if (name.length < 2)
    return false;
  return name[0] === '*' && name[1] === '.';
}

function convert(name, rr) {
  if (!isWild(rr.name))
    return rr;

  const x = util.splitName(name);
  const y = util.splitName(rr.name);

  assert(y.length > 0);

  if (x.length < y.length)
    return rr;

  rr = rr.clone();

  y[0] = x[x.length - y.length];

  rr.name = `${y.join('.')}.`;

  return rr;
}

/*
 * Expose
 */

export default Zone;
