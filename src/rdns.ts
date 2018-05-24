/*!
 * rdns.js - replacement dns node.js module (recursive)
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

import API from "./api";
import Cache from "./cache";
import Hints from "./hints";
import RecursiveResolver, {IRecursiveResolverOptions} from "./resolver/recursive";

let hints = null;

const cache = new Cache();

function createResolver(options?: IRecursiveResolverOptions) {
	if (!hints)
		hints = Hints.fromRoot();

	const resolver = new RecursiveResolver(options);

	if (!options.hints)
		resolver.hints = hints.clone();

	if (!options.cache)
		resolver.cache = cache;

	return resolver;
}

export default API.make(createResolver, {
	tcp: true,
	edns: true,
	dnssec: true
});
