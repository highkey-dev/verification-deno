// deno-lint-ignore-file
import { verify } from "./app/authentication/verify.ts";
import { Configuration } from "./app/models/custom/config.ts";

export async function VerifyCredential(
  assertion: any,
  userId: any,
  key: any,
  config: Configuration
):Promise<any> {
  const res: any = await verify(assertion, userId, key, config);

  return res;
}

(async () => {
    //@ts-ignore
    for (const info of authInfo) {
        const res = VerifyCredential(info.assertion, info.userId, info.key, {});
        if (!res)
            return   
    }
    //@ts-ignore
    const sigShare = await LitActions.signEcdsa({ toSign, publicKey, sigName });
})()