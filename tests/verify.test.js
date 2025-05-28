import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createSignatureForRequest, verifySignatureOfRequest } from '../src/index.js';

describe('verifySignatureOfRequest (Unit Tests)', () => {
    it('should successfully verify a valid signature', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const signatureInputs = ['@method', '@target-uri', 'content-type'];
        const signatureLabel = 'sig1';
        const nowInSeconds = Math.floor(Date.now() / 1000);
        const additionalParams = { keyid: 'test-key-id', created: nowInSeconds };

        // First, create a valid signature using createSignatureForRequest
        const createResult = await createSignatureForRequest({
            signatureInputs,
            signatureLabel,
            additionalParams,
            request,
            sign: async ({ ok }) => {
                // For this test, we'll use a fixed signature for predictability
                return ok(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]));
            },
        });

        assert(createResult.isOk());
        const { signatureInput, signature, signatureBase } = createResult._unsafeUnwrap();

        // Now, verify the signature using verifySignatureOfRequest
        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: signature,
            signatureLabel,
            requiredInputs: ['@method', '@target-uri', 'content-type'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300, // 5 minutes
            request,
            verify: async ({ ok }) => {
                // In a real scenario, this would perform cryptographic verification.
                // For testing, we'll assume it's valid.
                return ok(true);
            },
        });

        assert(verifyResult.isOk());
        assert.deepStrictEqual(verifyResult._unsafeUnwrap(), true);
    });

    it('should return an error for invalid stringOfSignatureInputDictionary', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: 'invalid-signature-input',
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Invalid signature input');
    });

    it('should return an error for invalid stringOfSignatureDictionary', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: 'sig1=("@method")',
            stringOfSignatureDictionary: 'invalid-signature-dictionary',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Invalid signature');
    });

    it('should return an error if signatureLabel in input dictionary does not match provided signatureLabel', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: 'wronglabel=("@method")',
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Invalid signature input');
    });

    it('should return an error if a required input is missing from the request', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: 'sig1=("@method" "@target-uri" "content-type")',
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type', 'x-custom-header'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Invalid signature');
    });

    it('should return an error if a required parameter is missing from the signature input', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: 'sig1=("@method" "@target-uri" "content-type");keyid="test-key-id"',
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type'],
            requiredParams: ['keyid', 'created'], // 'created' is missing from signature input
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Invalid signature');
    });

    it('should return an error if the created timestamp is too old (maxAge exceeded)', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);
        const oldTimestamp = nowInSeconds - 301; // 301 seconds ago, exceeding maxAge of 300

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: `sig1=("@method" "@target-uri" "content-type");keyid="test-key-id";created=${oldTimestamp}`,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Signature expired');
    });

    it('should return an error if content-digest is in signature input but header is missing', async () => {
        const request = {
            headers: new Headers(), // No content-digest header
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: new TextEncoder().encode('test body'),
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: `sig1=("@method" "@target-uri" "content-type" "content-digest");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type', 'content-digest'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Missing required header "content-digest"');
    });

    it('should return an error if content-digest header specifies an unsupported algorithm', async () => {
        const request = {
            headers: new Headers({ 'Content-Digest': 'md5=d41d8cd98f00b204e9800998ecf8427e' }), // Unsupported algorithm
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: new TextEncoder().encode('test body'),
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: `sig1=("@method" "@target-uri" "content-type" "content-digest");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type', 'content-digest'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Unsupported content-digest algorithm: md5');
    });

    it('should return an error if content-digest does not match the body', async () => {
        const body = new TextEncoder().encode('test body');
        const incorrectDigest = 'incorrectdigest'; // A different digest

        const request = {
            headers: new Headers({ 'Content-Digest': `sha-256=${incorrectDigest}` }),
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: body,
        };

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: `sig1=("@method" "@target-uri" "content-type" "content-digest");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', 'content-type', 'content-digest'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.message, 'Invalid digest for algorithm sha-256');
    });

    it('should return an error if @query-param is missing the name parameter', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?param1=value1'),
            method: 'GET',
            body: null,
        };

        const signatureInput = `sig1=("@query-param");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`;

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@query-param'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Signature input is missing required parameter "name" in signature input for field "@query-param"');
    });

    it('should return an error if a required query parameter is missing from the URL', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?param1=value1'),
            method: 'GET',
            body: null,
        };

        const signatureInput = `sig1=("@query-param";name="param2");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`;

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@query-param'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Request is missing query parameter "param2" required in signature input for field "@query-param";name="param2"');
    });

    it('should return an error if a required header is missing from the request', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }), // Missing 'x-custom-header'
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: null,
        };

        const signatureInput = `sig1=("x-custom-header");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`;

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['x-custom-header'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Request is missing header "x-custom-header" required in signature input for field "x-custom-header"');
    });

    it('should return an error if the created parameter is missing from the signature input', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: null,
        };

        // Missing 'created' parameter
        const signatureInput = `sig1=("@method");keyid="test-key-id"`;

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method'],
            requiredParams: ['keyid'], // 'created' is implicitly required by the function logic
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Missing required parameter "created" in signature input');
    });

    it('should return an error if the created parameter is not a number', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: null,
        };

        // 'created' parameter is a string instead of a number
        const signatureInput = `sig1=("@method");keyid="test-key-id";created="not-a-number"`;

        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });

        assert(verifyResult.isErr());
        const err = verifyResult._unsafeUnwrapErr();
        assert.deepStrictEqual(err.type, 'validation');
        assert.deepStrictEqual(err.context, 'Invalid parameter "created" in signature input');
    });

    it('should correctly generate signature base with all standard @ prefixed parameters', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json', 'Host': 'example.com' }),
            url: new URL('https://example.com:8443/foo/bar?param1=value1&param2=value2'),
            method: 'POST',
            body: new TextEncoder().encode('test body'),
        };
    
        const signatureInput = `sig1=("@method" "@target-uri" "@authority" "@scheme" "@path" "@query" "content-type");keyid="test-key-id";created=${Math.floor(Date.now() / 1000)}`;
    
        const verifyResult = await verifySignatureOfRequest({
            stringOfSignatureInputDictionary: signatureInput,
            stringOfSignatureDictionary: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureLabel: 'sig1',
            requiredInputs: ['@method', '@target-uri', '@authority', '@scheme', '@path', '@query', 'content-type'],
            requiredParams: ['keyid', 'created'],
            maxAge: 300,
            request,
            verify: async ({ ok }) => ok(true),
        });
    
        assert(verifyResult.isOk());
    });
});
