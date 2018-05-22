/*!
 * constants.js - constants for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 *
 * Resources:
 *   https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 */

'use strict';

/**
 * Message Opcodes
 * @enum {Number}
 * @default
 */

export enum Opcode {
	QUERY = 0,
	IQUERY = 1,
	STATUS = 2,
	// 3 is unassigned
	NOTIFY = 4,
	UPDATE = 5
	// 6-15 are unassigned
}

/**
 * Message Flags
 * @enum {Number}
 * @default
 */

export enum Flag {
	QR = 1 << 15, // query/response (response=1)
	AA = 1 << 10, // authoritative
	TC = 1 << 9,  // truncated
	RD = 1 << 8,  // recursion desired
	RA = 1 << 7,  // recursion available
	Z = 1 << 6,  // Z
	AD = 1 << 5,  // authenticated data
	CD = 1 << 4  // checking disabled
}

/**
 * Response Codes (rcodes)
 * @see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 * @enum {Number}
 * @default
 */

export enum Code {
	NOERROR = 0, // No Error
	SUCCESS = 0, // No Error
	FORMERR = 1, // Format Error
	SERVFAIL = 2, // Server Failure
	NXDOMAIN = 3, // Non-Existent Domain
	NOTIMP = 4, // Not Implemented
	REFUSED = 5, // Query Refused
	YXDOMAIN = 6, // Name Exists when it should not
	YXRRSET = 7, // RR Set Exists when it should not
	NXRRSET = 8, // RR Set that should exist does not
	NOTAUTH = 9, // Server Not Authoritative for zone
	NOTZONE = 10, // Name not contained in zone

	// 11-15 are unassigned

	// EDNS
	BADSIG = 16, // TSIG Signature Failure
	BADVERS = 16, // Bad OPT Version
	BADKEY = 17, // Key not recognized
	BADTIME = 18, // Signature out of time window
	BADMODE = 19, // Bad TKEY Mode
	BADNAME = 20, // Duplicate key name
	BADALG = 21, // Algorithm not supported
	BADTRUNC = 22, // Bad Truncation
	BADCOOKIE = 23, // Bad/missing Server Cookie

	// 24-3840 are unassigned

	// 3841-4095 reserved for private use

	// 4096-65534 unassigned

	RESERVED = 65535
}

/**
 * Record Types (rrtypes)
 * @enum {Number}
 * @default
 */
export enum RecordType {
	UNKNOWN = 0,
	A = 1,
	NS = 2,
	MD = 3, // obsolete
	MF = 4, // obsolete
	CNAME = 5,
	SOA = 6,
	MB = 7, // experimental
	MG = 8, // experimental
	MR = 9, // experimental
	NULL = 10, // obsolete
	WKS = 11, // deprecated
	PTR = 12,
	HINFO = 13, // not-in-use
	MINFO = 14, // experimental
	MX = 15,
	TXT = 16,
	RP = 17,
	AFSDB = 18,
	X25 = 19, // not-in-use
	ISDN = 20, // not-in-use
	RT = 21, // not-in-use
	NSAP = 22, // not-in-use
	NSAPPTR = 23, // not-in-use
	SIG = 24, // obsolete
	KEY = 25, // obsolete
	PX = 26, // not-in-use
	GPOS = 27, // deprecated
	AAAA = 28,
	LOC = 29,
	NXT = 30, // obsolete
	EID = 31, // not-in-use
	NIMLOC = 32, // not-in-use (used to be NB)
	SRV = 33, // used to be NBSTAT
	ATMA = 34, // not-in-use
	NAPTR = 35,
	KX = 36,
	CERT = 37,
	A6 = 38, // historic
	DNAME = 39,
	SINK = 40, // unimpl (joke?)
	OPT = 41, // impl (pseudo-record, edns)
	APL = 42, // not-in-use
	DS = 43,
	SSHFP = 44,
	IPSECKEY = 45,
	RRSIG = 46,
	NSEC = 47,
	DNSKEY = 48,
	DHCID = 49,
	NSEC3 = 50,
	NSEC3PARAM = 51,
	TLSA = 52,
	SMIMEA = 53,

	// 54 is unassigned

	HIP = 55,
	NINFO = 56, // proposed
	RKEY = 57, // proposed
	TALINK = 58, // proposed
	CDS = 59,
	CDNSKEY = 60,
	OPENPGPKEY = 61,
	CSYNC = 62,

	// 63-98 are unassigned

	SPF = 99, // obsolete
	UINFO = 100, // obsolete
	UID = 101, // obsolete
	GID = 102, // obsolete
	UNSPEC = 103, // obsolete
	NID = 104,
	L32 = 105,
	L64 = 106,
	LP = 107,
	EUI48 = 108,
	EUI64 = 109,

	// 110-248 are unassigned

	TKEY = 249,
	TSIG = 250,
	IXFR = 251, // unimpl (pseudo-record)
	AXFR = 252, // unimpl (pseudo-record)
	MAILB = 253, // experimental, unimpl (qtype)
	MAILA = 254, // obsolete, unimpl (qtype)

	ANY = 255, // impl (qtype)
	URI = 256,
	CAA = 257,
	AVC = 258, // proposed
	DOA = 259, // proposed
	// OX: 260, // proposed successor to DOA?

	// 260-32767 are unassigned

	TA = 32768,
	DLV = 32769,

	// 32770-65279 are unassigned
	// 65280-65534 reserved for private use

	RESERVED = 65535 // unimpl
}

/**
 * Question and Record Classes (qclass/rclass)
 * @enum {Number}
 * @default
 */

export enum QuestionClass {
	RESERVED0 = 0,
	IN = 1, // INET

	// 2 is unassigned (used to be CSNET/CS)

	CH = 3, // CHAOS
	HS = 4, // HESIOD

	// 5-253 are unassigned

	NONE = 254,
	ANY = 255,

	// 256-65279 are unassigned
	// 65280-65534 are reserved for private use

	RESERVED65535 = 65535
}

/**
 * EDNS0 Flags
 * @enum {Number}
 * @default
 */
export enum EFlag {
	DO = 1 << 15 // DNSSEC OK
	// 1-15 are reserved
}

/**
 * EDNS0 Option Codes
 * @enum {Number}
 * @default
 */

export enum EOption {
	RESERVED = 0, // None
	LLQ = 1, // Long Lived Queries
	UL = 2, // Update Lease Draft
	NSID = 3, // Nameserver Identifier
	DAU = 5, // DNSSEC Algorithm Understood
	DHU = 6, // DS Hash Understood
	N3U = 7, // NSEC3 Hash Understood
	SUBNET = 8, // Client Subnet
	EXPIRE = 9, // Expire
	COOKIE = 10, // Cookie
	TCPKEEPALIVE = 11, // TCP Keep-Alive
	PADDING = 12, // Padding
	CHAIN = 13, // Chain
	KEYTAG = 14, // EDNS Key Tag

	// 15-26945 are unassigned

	// DEVICEID: 26946,

	// 26947-65000 are unassigned

	LOCAL = 65001, // Beginning of range reserved for local/experimental use
	LOCALSTART = 65001, // Beginning of range reserved for local/experimental use

	// 65001-65534 are reserved for experimental use

	LOCALEND = 65534 // End of range reserved for local/experimental use

	// 65535 is reserved
}

/**
 * DNSKEY flag values.
 * @enum {Number}
 * @default
 */
export enum KeyFlag {
	SEP = 1,
	REVOKE = 1 << 7,
	ZONE = 1 << 8
}

/**
 * DNSSEC encryption algorithm codes.
 * @enum {Number}
 * @default
 */
export enum EncAlg {
	// _: 0,
	RSAMD5 = 1,
	DH = 2,
	DSA = 3,
	// _: 4,
	RSASHA1 = 5,
	DSANSEC3SHA1 = 6,
	RSASHA1NSEC3SHA1 = 7,
	RSASHA256 = 8,
	// _: 9,
	RSASHA512 = 10,
	// _: 11,
	ECCGOST = 12,
	ECDSAP256SHA256 = 13,
	ECDSAP384SHA384 = 14,
	ED25519 = 15,
	ED448 = 16,
	INDIRECT = 252,
	PRIVATEDNS = 253, // Private (experimental keys)
	PRIVATEOID = 254
}

/**
 * DNSSEC hashing algorithm codes.
 * @enum {Number}
 * @default
 */
export enum HashAlg {
	// _: 0,
	SHA1 = 1, // RFC 4034
	SHA256 = 2, // RFC 4509
	GOST94 = 3, // RFC 5933
	SHA384 = 4, // Experimental
	SHA512 = 5 // Experimental
}

/**
 * Corresponding hashes for algorithms.
 * @const {Object}
 */

export const algHashes = {
	[EncAlg.RSAMD5]: null, // Deprecated in RFC 6725 (introduced in rfc2537)
	[EncAlg.RSASHA1]: HashAlg.SHA1,
	[EncAlg.RSASHA1NSEC3SHA1]: HashAlg.SHA1,
	[EncAlg.RSASHA256]: HashAlg.SHA256,
	[EncAlg.ECDSAP256SHA256]: HashAlg.SHA256,
	[EncAlg.ECDSAP384SHA384]: HashAlg.SHA384,
	[EncAlg.RSASHA512]: HashAlg.SHA512,
	[EncAlg.ED25519]: HashAlg.SHA256
};

/**
 * NSEC3 hashes.
 * @enum {Number}
 * @default
 */

export enum NsecHash {
	SHA1 = 1
}

/**
 * CERT types (rfc4398).
 * @enum {Number}
 * @default
 */

export enum CertType {
	// 0 reserved
	PKIX = 1,
	SPKI = 2,
	PGP = 3,
	IPKIX = 4,
	ISPKI = 5,
	IPGP = 6,
	ACPKIX = 7,
	IACPKIX = 8,
	// 9-252 unassigned
	URI = 253,
	OID = 254
	// 255 reserved
	// 256-65279 unassigned
	// 65280-65534 experimental
	// 65535 reserved
}

/**
 * DANE usages.
 * @enum {Number}
 * @default
 */
export enum DaneUsage {
	CAC = 0, // CA constraint
	SCC = 1, // Service certificate constraint
	TAA = 2, // Trust anchor assertion
	DIC = 3, // Domain-issued certificate
	// 4-254 are unassigned
	PRIVATE = 255 // Private Use
}

/**
 * DANE selectors.
 * @enum {Number}
 * @default
 */
export enum DaneSelector {
	FULL = 0, // Full Certificate
	SPKI = 1, // SubjectPublicKeyInfo
	// 2-254 are unassigned
	PRIVATE = 255 // Private Use
}

/**
 * DANE matching types.
 * @enum {Number}
 * @default
 */
export enum DaneMatchingType {
	NONE = 0, // No hash used
	SHA256 = 1,
	SHA512 = 2,
	// 3-254 are unassigned
	PRIVATE = 255 // Private Use
}


/**
 * SSHFP algorithms.
 * @enum {Number}
 * @default
 */
export enum SSHAlg {
	RSA = 1,
	DSA = 2,
	ECDSA = 3,
	ED25519 = 4
}

/**
 * SSHFP hashes.
 * @enum {Number}
 * @default
 */
export enum SSHHash {
	SHA1 = 1,
	SHA256 = 2
}

/**
 * TSIG hash algorithms.
 * @const {Object}
 * @default
 */
export enum TSigAlg {
	MD5 = 'hmac-md5.sig-alg.reg.int.',
	SHA1 = 'hmac-sha1.',
	SHA256 = 'hmac-sha256.',
	SHA512 = 'hmac-sha512.'
}

/**
 * TSIG hash algorithms by value.
 * @const {Object}
 * @default
 */

export const tsigAlgsByVal = {
	[TSigAlg.MD5]: 'MD5',
	[TSigAlg.SHA1]: 'SHA1',
	[TSigAlg.SHA256]: 'SHA256',
	[TSigAlg.SHA512]: 'SHA512'
};

/**
 * TKEY modes.
 * @enum {Number}
 * @default
 */
export enum TKeyMode {
	RESERVED = 0, // reserved
	SERVER = 1, // server assignment
	DH = 2, // Diffie-Hellman exchange
	GSS = 3, // GSS-API negotiation
	RESOLVER = 4, // resolver assignment
	DELETE = 5 // key deletion
	// 6-65534 unassigned
	// 65535 reserved
}

/**
 * For RFC1982 (Serial Arithmetic) calculations in 32 bits.
 * @const {Number}
 * @default
 */
export const YEAR68 = (1 << 31) >>> 0;

/**
 * Equator.
 * @const {Number}
 * @default
 */
export const LOC_EQUATOR = (1 << 31) >>> 0; // RFC 1876, Section 2.

/**
 * Prime meridian.
 * @const {Number}
 * @default
 */
export const LOC_PRIMEMERIDIAN = (1 << 31) >>> 0; // RFC 1876, Section 2.

/**
 * Location hours.
 * @const {Number}
 * @default
 */
export const LOC_HOURS = 60 * 1000;

/**
 * Location degrees.
 * @const {Number}
 * @default
 */
export const LOC_DEGREES = 60 * LOC_HOURS;

/**
 * Altitude base.
 * @const {Number}
 * @default
 */
export const LOC_ALTITUDEBASE = 100000;

/**
 * Max domain name length.
 * @const {Number}
 * @default
 */
export const MAX_NAME_SIZE = 255;

/**
 * Max label length.
 * @const {Number}
 * @default
 */
export const MAX_LABEL_SIZE = 63;

/**
 * Max udp size.
 * @const {Number}
 * @default
 */
export const MAX_UDP_SIZE = 512;

/**
 * Standard udp+edns size (rfc 2671).
 * @const {Number}
 * @default
 */
export const STD_EDNS_SIZE = 1280;

/**
 * Max udp+edns size.
 * @const {Number}
 * @default
 */
export const MAX_EDNS_SIZE = 4096;

/**
 * Max tcp size.
 * @const {Number}
 * @default
 */
export const MAX_MSG_SIZE = 65535;

/**
 * Default DNS port.
 * @const {Number}
 * @default
 */
export const DNS_PORT = 53;

/**
 * Default TTL.
 * @const {Number}
 * @default
 */
export const DEFAULT_TTL = 3600;

/*
 * Helpers
 */

function toSymbol(value: number, name: string, map: any, prefix: string, max: number, size: number): string {
	// if (typeof value !== 'number')
	// 	throw new Error(`'${name}' must be a number.`);

	if ((value & max) !== value)
		throw new Error(`Invalid ${name}: ${value}.`);

	const symbol = map[value];

	if (typeof symbol === 'string')
		return symbol;

	return `${prefix}${value.toString(10)}`;
}

function fromSymbol(symbol: string, name: string, map: any, prefix: string, max: number, size: number): number {
	// if (typeof symbol !== 'string')
	// 	throw new Error(`'${name}' must be a string.`);

	if (symbol.length > 64)
		throw new Error(`Unknown ${name}.`);

	const value = map[symbol];

	if (typeof value === 'number')
		return value;

	if (symbol.length <= prefix.length)
		throw new Error(`Unknown ${name}: ${symbol}.`);

	if (symbol.substring(0, prefix.length) !== prefix)
		throw new Error(`Unknown ${name}: ${symbol}.`);

	if (symbol.length > prefix.length + size)
		throw new Error(`Unknown ${name}: ${symbol}.`);

	let word = 0;

	for (let i = prefix.length; i < symbol.length; i++) {
		const ch = symbol.charCodeAt(i) - 0x30;

		if (ch < 0 || ch > 9)
			throw new Error(`Unknown ${name}: ${symbol}.`);

		word *= 10;
		word += ch;

		if (word > max)
			throw new Error(`Unknown ${name}: ${symbol}.`);
	}

	return word;
}

function isSymbol(symbol: string, name: string, map: any, prefix: string, max: number, size: number): boolean {
	// if (typeof symbol !== 'string')
	// 	throw new Error(`'${name}' must be a string.`);

	try {
		fromSymbol(symbol, name, map, prefix, max, size);
		return true;
	} catch (e) {
		return false;
	}
}

export function opcodeToString(opcode) {
	return toSymbol(opcode, 'opcode', Opcode, 'OPCODE', 0x0f, 2);
}

export function stringToOpcode(symbol) {
	return fromSymbol(symbol, 'opcode', Opcode, 'OPCODE', 0x0f, 2);
}

export function isOpcodeString(symbol) {
	return isSymbol(symbol, 'opcode', Opcode, 'OPCODE', 0x0f, 2);
}

export function codeToString(code) {
	return toSymbol(code, 'code', Code, 'RCODE', 0x0f, 2);
}

export function stringToCode(symbol) {
	return fromSymbol(symbol, 'code', Code, 'RCODE', 0x0fff, 4);
}

export function isCodeString(symbol) {
	return isSymbol(symbol, 'code', Code, 'RCODE', 0x0fff, 4);
}

export function typeToString(type) {
	return toSymbol(type, 'type', RecordType, 'TYPE', 0xffff, 5);
}

export function stringToType(symbol) {
	return fromSymbol(symbol, 'type', RecordType, 'TYPE', 0xffff, 5);
}

export function isTypeString(symbol) {
	return isSymbol(symbol, 'type', RecordType, 'TYPE', 0xffff, 5);
}

export function classToString(class_) {
	return toSymbol(class_, 'class', QuestionClass, 'CLASS', 0xffff, 5);
}

export function stringToClass(symbol) {
	return fromSymbol(symbol, 'class', QuestionClass, 'CLASS', 0xffff, 5);
}

export function isClassString(symbol) {
	return isSymbol(symbol, 'class', QuestionClass, 'CLASS', 0xffff, 5);
}

export function optionToString(option) {
	return toSymbol(option, 'option', EOption, 'OPTION', 0xffff, 5);
}

export function stringToOption(symbol) {
	return fromSymbol(symbol, 'option', EOption, 'OPTION', 0xffff, 5);
}

export function isOptionString(symbol) {
	return isSymbol(symbol, 'option', EOption, 'OPTION', 0xffff, 5);
}

export function algToString(alg) {
	return toSymbol(alg, 'algorithm', EncAlg, 'ALG', 0xff, 3);
}

export function stringToAlg(symbol) {
	return fromSymbol(symbol, 'algorithm', EncAlg, 'ALG', 0xff, 3);
}

export function isAlgString(symbol) {
	return isSymbol(symbol, 'algorithm', EncAlg, 'ALG', 0xff, 3);
}

export function hashToString(hash) {
	return toSymbol(hash, 'hash', HashAlg, 'HASH', 0xff, 3);
}

export function stringToHash(symbol) {
	return fromSymbol(symbol, 'hash', HashAlg, 'HASH', 0xff, 3);
}

export function isHashString(symbol) {
	return isSymbol(symbol, 'hash', HashAlg, 'HASH', 0xff, 3);
}

/*
 * Expose
 */
export {toSymbol as _toSymbol}
export {fromSymbol as _fromSymbol}
export {isSymbol as _isSymbol}
