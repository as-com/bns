/*!
 * dns.js - replacement dns node.js module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import API from "./api";
import Hosts from "./hosts";
import ResolvConf from "./resolvconf";
import StubResolver from "./resolver/stub";

let conf = null;
let hosts = null;

function createResolver(options, servers) {
	if (!conf)
		conf = ResolvConf.fromSystem();

	if (!hosts)
		hosts = Hosts.fromSystem();

	const resolver = new StubResolver(options);

	if (!options.conf)
		resolver.conf = conf.clone();

	if (!options.hosts)
		resolver.hosts = hosts.clone();

	if (servers)
		resolver.setServers(servers);

	return resolver;
}

export default API.make(createResolver, {
	tcp: true,
	edns: false,
	dnssec: false
});
