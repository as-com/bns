/*!
 * bns.js - dns module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

import * as dane from "./dane";
import * as constants from "./constants";
import * as dnssec from "./dnssec";
import * as encoding from "./encoding";
import * as hsig from "./hsig";
import * as nsec3 from "./nsec3";
import * as sig0 from "./sig0";
import * as smimea from "./smimea";
import * as sshfp from "./sshfp";
import * as tlsa from "./tlsa";
import * as tsig from "./tsig";
import * as util from "./util";
import * as wire from "./wire";

export {default as API} from "./api";
export {default as Authority} from "./authority";
export {default as AuthServer} from "./server/auth";
export {default as Cache} from "./cache";

export {default as dns} from "./dns";
export {default as DNSResolver} from "./resolver/dns";
export {default as DNSServer} from "./server/dns";
export {default as DNSError} from "./error";
export {default as Hints} from "./hints";
export {default as Hosts} from "./hosts";
export {default as rdns} from "./rdns";
export {default as RecursiveResolver} from "./resolver/recursive";
export {default as RecursiveServer} from "./server/recursive";
export {default as ResolvConf} from "./resolvconf";
export {default as ROOT_HINTS} from "./roothints";
export {default as StubResolver} from "./resolver/stub";
export {default as StubServer} from "./server/stub";
export {default as Zone} from "./zone";

export {constants, dane, dnssec, encoding, hsig, nsec3, sig0, smimea, sshfp, tlsa, tsig, util, wire};
