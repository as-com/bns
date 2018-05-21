/*!
 * tlsa.js - TLSA for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/tlsa.go
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6698
 */

'use strict';

import assert from "assert";
import {matchingTypes, selectors, usages} from "./dane";
import * as util from "./util";
import {classes, Record, TLSARecord, types} from "./wire";

/*
 * TLSA
 */

const tlsa = exports;

tlsa.create = function create(cert, name, protocol, port, options = {}) {
	assert(Buffer.isBuffer(cert));
	assert(options && typeof options === 'object');

	let {ttl, usage, selector, matchingType} = options;

	if (ttl == null)
		ttl = 3600;

	if (usage == null)
		usage = usages.DIC;

	if (selector == null)
		selector = selectors.SPKI;

	if (matchingType == null)
		matchingType = matchingTypes.SHA256;

	assert((ttl >>> 0) === ttl);
	assert((usage & 0xff) === usage);
	assert((selector & 0xff) === selector);
	assert((matchingType & 0xff) === matchingType);

	const rr = new Record();
	const rd = new TLSARecord();

	rr.name = tlsa.encodeName(name, protocol, port);
	rr.type = types.TLSA;
	rr.class = classes.IN;
	rr.ttl = ttl;
	rr.data = rd;
	rd.usage = usage;
	rd.selector = selector;
	rd.matchingType = matchingType;

	const hash = dane.sign(cert, selector, matchingType);

	if (!hash)
		throw new Error('Unknown selector or matching type.');

	rd.certificate = hash;

	return rr;
};

tlsa.verify = function verify(rr, cert, name, protocol, port) {
	assert(rr instanceof Record);
	assert(rr.type === types.TLSA);

	const rd = rr.data;

	if (protocol != null) {
		if (!tlsa.verifyName(rr, name, protocol, port))
			return false;
	}

	return dane.verify(cert, rd.selector, rd.matchingType, rd.certificate);
};

tlsa.verifyName = function verifyName(rr, name, protocol, port) {
	assert(rr instanceof Record);
	assert(rr.type === types.TLSA);
	const encoded = tlsa.encodeName(name, protocol, port);
	return util.equal(rr.name, encoded);
};

tlsa.encodeName = function encodeName(name, protocol, port) {
	assert(util.isName(name));
	assert(name.indexOf('_') === -1);
	assert(typeof protocol === 'string');
	assert(protocol.length <= 62);
	assert(protocol.indexOf('.') === -1);
	assert((port & 0xffff) === port);

	const encoded = util.fqdn(`_${port.toString(10)}._${protocol}.${name}`);

	assert(util.isName(encoded));

	return encoded;
};

tlsa.decodeName = function decodeName(name) {
	assert(util.isName(name));

	const labels = util.split(name);

	assert(labels.length >= 3);

	const port = util.label(name, labels, 0);
	const protocol = util.label(name, labels, 1);

	assert(port.length > 0);
	assert(protocol.length > 0 && protocol.length <= 63);
	assert(port[0] === '_');
	assert(protocol[0] === '_');

	return {
		name: util.fqdn(util.from(name, labels, 2)),
		protocol: protocol.substring(1).toLowerCase(),
		port: util.parseU16(port.substring(1))
	};
};
