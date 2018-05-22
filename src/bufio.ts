declare module "bufio" {
	// TODO

	export function write(size: number);

	export function read(data: any);

	export class EncodingError extends Error {
		constructor(off: number, str: string);
	}

	export class Struct { // TODO
		inject(obj);

		clone();

		/*
         * Bindable
         */

		getSize(extra?): number;

		write(bw, extra?);

		read(br, extra?): this;

		toString(...args: any[]): string;

		fromString(str, extra?): this;

		getJSON(): any;

		fromJSON(json, extra?): this;

		fromOptions(options, extra?): this;

		from(options, extra?): this;

		format(): this;

		/*
         * API
         */

		encode(extra?): Buffer;

		decode(data, extra?): this;

		toHex(extra?): string;

		fromHex(str, extra?): this;

		toBase64(extra?): string;

		fromBase64(str, extra?): this;

		toJSON(): this;

		inspect(): this;

		/*
         * Static API
         */

		static read<T extends Struct>(br, extra?): T;

		static decode(data, extra?);

		static fromHex<T extends Struct>(str, extra?): T;

		static fromBase64<T extends Struct>(str, extra?): T;

		static fromString<T extends Struct>(str, extra?): T;

		static fromJSON<T extends Struct>(json, extra?): T;

		static fromOptions<T extends Struct>(options, extra?): T;

		static from<T extends Struct>(options, extra?): T;

		/*
         * Aliases
         */

		toWriter(bw, extra?); // TODO

		fromReader(br, extra?): this;

		toRaw(extra?): Buffer;

		fromRaw(data, extra?): this;

		/*
         * Static Aliases
         */

		static fromReader<T extends Struct>(br, extra?): Struct;

		static fromRaw<T extends Struct>(data, extra?): T
	}
}
