 import {
  generatePublicKeyCredentialCreationOptions
} from "./app/authentication/util.ts";


(() => {
    //@ts-ignore: function injected from lit's action context
    const options = JSON.stringify(generatePublicKeyCredentialCreationOptions(rpId, rpName));
    //@ts-ignore: function injected from lit's action context
    setResponse({response: options});
})()