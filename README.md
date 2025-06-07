# http-msg-sig

`http-msg-sig` is a JavaScript library for creating and verifying HTTP Message Signatures, adhering to the [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) specification. It provides a robust and type-safe way to handle message integrity and authentication using `neverthrow` for explicit error handling.

## Installation

To install the package, use npm or yarn:

```bash
npm install http-msg-sig
# or
yarn add http-msg-sig
```

## Usage

This library exposes two primary asynchronous functions: `createSignatureForRequest` for generating signatures and `verifySignatureOfRequest` for validating them. Both functions return `neverthrow` `Result` types, allowing for clear and explicit error handling.

### Creating a Signature

To create an HTTP message signature, you need to provide request details, signature inputs (headers, pseudo-headers, query parameters), a signature label, and a `sign` function that performs the cryptographic signing.

```ts
import { createSignatureForRequest } from 'http-msg-sig';

async function exampleCreateSignature() {
    const request = {
        headers: new Headers({
            'Content-Type': 'application/json',
            'Date': new Date().toUTCString(),
            'Host': 'example.com'
        }),
        url: new URL('https://example.com/data?param1=value1'),
        method: 'POST',
    };

    // Your custom signing function (e.g., using a private key)
    const signFunction = async ({ signatureBase, params, ok, err }: {
        signatureBase: string;
        params: Record<string, unknown>;
        ok: <T>(value: T) => Result<T, never>;
        err: <E>(error: E) => Result<never, E>;
    }) => {
        // In a real application, you would use a cryptographic library here
        // For demonstration, we'll just return a dummy signature
        const encoder = new TextEncoder();
        const data = encoder.encode(signatureBase);
        // Replace with actual signing logic
        const dummySignature = new Uint8Array([1, 2, 3, 4, 5]); 
        return ok(dummySignature.buffer);
    };

    const result = await createSignatureForRequest({
        signatureInputs: [
            '@method',
            '@target-uri',
            'content-type',
            'date',
            { component: '@query-param', parameters: { name: 'param1' } }
        ],
        signatureLabel: 'sig1',
        additionalParams: { alg: 'ed25519', keyid: 'test-key-01' },
        request,
        sign: signFunction,
    });

    if (result.isOk()) {
        const { signatureInput, signature, signatureBase } = result.value;
        console.log('Signature Input:', signatureInput);
        console.log('Signature:', signature);
        console.log('Signature Base:', signatureBase);
        // You would typically add these to your HTTP request headers
    } else {
        console.error('Error creating signature:', result.error);
    }
}

exampleCreateSignature();
```

### Verifying a Signature

To verify an HTTP message signature, you need the original request details, the signature input and signature strings (usually from request headers), the signature label, required inputs and parameters, a maximum age for the signature, and a `verify` function that performs the cryptographic verification.

```ts
import { verifySignatureOfRequest } from 'http-msg-sig';

async function exampleVerifySignature() {
    const request = {
        headers: new Headers({
            'Content-Type': 'application/json',
            'Date': new Date().toUTCString(),
            'Host': 'example.com',
            'Signature-Input': 'sig1=(@method @target-uri content-type date @query-param;name="param1");alg="ed25519";keyid="test-key-01"',
            'Signature': 'sig1=:AQIDBAU='
        }),
        url: new URL('https://example.com/data?param1=value1'),
        method: 'POST',
        body: JSON.stringify({ key: 'value' }),
    };

    // Your custom verification function (e.g., using a public key)
    const verifyFunction = async ({ signatureBase, params, signature, ok, err }: {
        signatureBase: string;
        params: Record<string, unknown>;
        signature: ArrayBuffer;
        ok: <T>(value: T) => Result<T, never>;
        err: <E>(error: E) => Result<never, E>;
    }) => {
        // In a real application, you would use a cryptographic library here
        // and verify the signature against the signatureBase and a public key
        // For demonstration, we'll just return true
        const expectedSignature = new Uint8Array([1, 2, 3, 4, 5]);
        if (signature.byteLength === expectedSignature.byteLength &&
            signature.every((val, i) => val === expectedSignature[i])) {
            return ok(true);
        } else {
            return err({ type: 'verification', message: 'Signature mismatch' });
        }
    };

    const result = await verifySignatureOfRequest({
        stringOfSignatureInputDictionary: request.headers.get('Signature-Input'),
        stringOfSignatureDictionary: request.headers.get('Signature'),
        signatureLabel: 'sig1',
        requiredInputs: [
            '@method',
            '@target-uri',
            'content-type',
            'date',
            { component: '@query-param', parameters: { name: 'param1' } }
        ],
        requiredParams: ['alg', 'keyid'],
        maxAge: 300, // 5 minutes
        request,
        verify: verifyFunction,
    });

    if (result.isOk()) {
        console.log('Signature verification successful!');
    } else {
        console.error('Signature verification failed:', result.error);
    }
}

exampleVerifySignature();
```

## API

### `createSignatureForRequest(params)`

Generates an HTTP message signature.

-   `params.signatureInputs`: Array of strings or objects defining components to be signed (e.g., `@method`, `date`, `{ component: '@query-param', parameters: { name: 'param1' } }`).
-   `params.signatureLabel`: A label for the signature (e.g., `'sig1'`).
-   `params.additionalParams`: Object of additional parameters to include in the signature input.
-   `params.request`: The HTTP request object containing `headers`, `url`, `method`, and optional `body`.
-   `params.sign`: An asynchronous function `({ signatureBase, params, ok, err }) => Promise<Result<ArrayBuffer, Error>>` that performs the cryptographic signing.

Returns: `Promise<Result<{ signatureInput: string, signature: string, signatureBase: string }, Error>>`

### `verifySignatureOfRequest(params)`

Verifies an HTTP message signature.

-   `params.stringOfSignatureInputDictionary`: The `Signature-Input` header value.
-   `params.stringOfSignatureDictionary`: The `Signature` header value.
-   `params.signatureLabel`: The label of the signature to verify.
-   `params.requiredInputs`: Array of strings or objects defining components that *must* be present in the signature input.
-   `params.requiredParams`: Array of strings defining parameters that *must* be present in the signature input.
-   `params.maxAge`: Maximum age in seconds for the signature to be considered valid.
-   `params.request`: The HTTP request object containing `headers`, `url`, `method`, and optional `body`.
-   `params.verify`: An asynchronous function `({ signatureBase, params, signature, ok, err }) => Promise<Result<true, Error>>` that performs the cryptographic verification.

Returns: `Promise<Result<true, Error>>`

## License

MIT License
