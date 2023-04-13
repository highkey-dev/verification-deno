// deno-lint-ignore-file
import { verify } from "./app/authentication/verify.ts";
import { Buffer } from "https://deno.land/std@0.173.0/node/internal/buffer.mjs";

(async () => {
    //@ts-ignore
    if (!authInfo || authInfo.length < 1) {
      throw new Error("Does not meet minimum verification requirements");
    }
    
    //@ts-ignore
    for (const info of authInfo) {
      //decode key info
      info.key.x = info.key.x.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
      info.key.y = info.key.y.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

      //decode attestation response info
      (info.assertion.response.authenticatorData as any) = new Uint8Array(Buffer.from(info.assertion.response.authenticatorData.data));
      (info.assertion.response.signature as any) =  new Uint8Array(Buffer.from(info.assertion.response.signature.data));
      (info.assertion.response.clientDataJSON as any) = new Uint8Array(Buffer.from(info.assertion.response.clientDataJSON.data));

      const res = verify(info.assertion, info.userId, info.key, {});
      if (!res)
        throw new Error(`signature could not be verified aborting signing`);   
    }

    //@ts-ignore
    const sigShare = await LitActions.signEcdsa({ toSign, publicKey, sigName });
})();
