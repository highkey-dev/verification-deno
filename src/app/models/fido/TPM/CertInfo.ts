import { Buffer } from "https://deno.land/std@0.162.0/node/buffer.ts";

export interface CertInfo {
	attested: {
		name: Buffer;
		nameAlg: string;
		qualifiedName: Buffer;
	};
	clockInfo: {
		clock: Buffer;
		resetCount: number;
		restartCount: number;
		safe: boolean;
	}
	extraData: Buffer;
	firmwareVersion: Buffer;
	magic: number;
	qualifiedSigner: Buffer;
	type: string;
}