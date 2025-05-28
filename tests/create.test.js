import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createSignatureForRequest } from '../src/index.js';
import { ok, err } from 'neverthrow';

describe('createSignatureForRequest (Unit Tests)', () => {
    it('should create a signature base with method, target-uri, and a header', async () => {
        const request = {
            headers: new Headers({ 'Content-Type': 'application/json' }),
            url: new URL('https://example.com/foo?bar=baz'),
            method: 'POST',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);
        const result = await createSignatureForRequest({
            signatureInputs: ['@method', '@target-uri', 'content-type'],
            signatureLabel: 'sig1',
            additionalParams: { keyid: 'test-key-id', created: nowInSeconds },
            request,
            sign: async ({ ok }) => {
                // In a real scenario, this would perform cryptographic signing.
                // For testing, we return a fixed Uint8Array.
                return ok(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]));
            },
        });

        const expectedSignatureBase = [
            '"@method": POST',
            '"@target-uri": https://example.com/foo?bar=baz',
            '"content-type": application/json',
            `"@signature-params": ("@method" "@target-uri" "content-type");keyid="test-key-id";created=${nowInSeconds}`,
        ];
        assert.deepStrictEqual(result, ok({
            signatureInput: `sig1=("@method" "@target-uri" "content-type");keyid="test-key-id";created=${nowInSeconds}`,
            signature: 'sig1=:AQIDBAUGBwgJAA==:',
            signatureBase: expectedSignatureBase.join('\n'),
        }));
    });

    it('should include @query-param correctly', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://example.com/path?param1=value1&param2=value2'),
            method: 'GET',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: ['@method', { component: '@query-param', parameters: { name: 'param1' } }],
            signatureLabel: 'sig2',
            additionalParams: { keyid: 'query-test', created: nowInSeconds },
            request,
            sign: async ({ signatureBase, params, ok, err }) => {
                return ok(new Uint8Array([1, 2, 3]));
            },
        });

        const expectedSignatureBase = [
            '"@method": GET',
            '"@query-param";name="param1": value1',
            `"@signature-params": ("@method" "@query-param";name="param1");keyid="query-test";created=${nowInSeconds}`,
        ];
        assert.deepStrictEqual(result, ok({
            signatureInput: `sig2=("@method" "@query-param";name="param1");keyid="query-test";created=${nowInSeconds}`,
            signature: 'sig2=:AQID:', // Base64 for new Uint8Array([1, 2, 3])
            signatureBase: expectedSignatureBase.join('\n'),
        }));
    });

    it('should return an error if a required header is missing', async () => {
        const request = {
            headers: new Headers(), // Missing 'Content-Type'
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: ['@method', 'content-type'],
            signatureLabel: 'sig3',
            additionalParams: { keyid: 'error-test', created: nowInSeconds },
            request,
            sign: async ({ signatureBase, params, ok, err }) => {
                return ok(new Uint8Array([1, 2, 3]));
            },
        });

        assert.deepStrictEqual(result, err({
            type: 'validation',
            message: 'Missing header: content-type',
            context: 'Request is missing header "content-type" required in signature input for field "content-type"',
        }));
    });

    it('should correctly include @authority, @scheme, @path, and @query', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://user:pass@sub.example.com:8080/path/to/file?query=string#hash'),
            method: 'GET',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: ['@method', '@authority', '@scheme', '@path', '@query'],
            signatureLabel: 'sig4',
            additionalParams: { keyid: 'uri-test', created: nowInSeconds },
            request,
            sign: async ({ ok }) => ok(new Uint8Array([1, 2, 3, 4])),
        });

        const expectedSignatureBase = [
            '"@method": GET',
            '"@authority": sub.example.com',
            '"@scheme": https',
            '"@path": /path/to/file',
            '"@query": ?query=string',
            `"@signature-params": ("@method" "@authority" "@scheme" "@path" "@query");keyid="uri-test";created=${nowInSeconds}`,
        ];

        assert.deepStrictEqual(result, ok({
            signatureInput: `sig4=("@method" "@authority" "@scheme" "@path" "@query");keyid="uri-test";created=${nowInSeconds}`,
            signature: 'sig4=:AQIDBA==:',
            signatureBase: expectedSignatureBase.join('\n'),
        }));
    });

    it('should correctly include @query when the URL has an empty query string', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://example.com/path'), // No query string
            method: 'GET',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: ['@method', '@query'],
            signatureLabel: 'sig5',
            additionalParams: { keyid: 'empty-query-test', created: nowInSeconds },
            request,
            sign: async ({ ok }) => ok(new Uint8Array([5, 6])),
        });

        const expectedSignatureBase = [
            '"@method": GET',
            '"@query": ',
            `"@signature-params": ("@method" "@query");keyid="empty-query-test";created=${nowInSeconds}`,
        ];

        assert.deepStrictEqual(result, ok({
            signatureInput: `sig5=("@method" "@query");keyid="empty-query-test";created=${nowInSeconds}`,
            signature: 'sig5=:BQY=:',
            signatureBase: expectedSignatureBase.join('\n'),
        }));
    });

    it('should return an error if @query-param is missing the name parameter in createSignatureForRequest', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://example.com/foo?param1=value1'),
            method: 'GET',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: [{ component: '@query-param', parameters: { name: '' } }],
            signatureLabel: 'sig6',
            additionalParams: { keyid: 'missing-name-test', created: nowInSeconds },
            request,
            sign: async ({ ok }) => ok(new Uint8Array([1])),
        });

        assert.deepStrictEqual(result, err({
            type: 'validation',
            message: 'Invalid signature input',
            context: 'Signature input is missing required parameter "name" in signature input for field "@query-param";name=""',
        }));
    });

    it('should return an error if a required query parameter is missing from the URL in createSignatureForRequest', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://example.com/foo?param1=value1'),
            method: 'GET',
            body: null,
        };
        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: [{ component: '@query-param', parameters: { name: 'param2' } }],
            signatureLabel: 'sig7',
            additionalParams: { keyid: 'missing-query-param-test', created: nowInSeconds },
            request,
            sign: async ({ ok }) => ok(new Uint8Array([1])),
        });

        assert.deepStrictEqual(result, err({
            type: 'validation',
            message: 'Missing query parameter: param2',
            context: 'Request is missing query parameter "param2" required in signature input for field "@query-param";name="param2"',
        }));
    });

    it('should return an error if the sign function returns an error result', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: ['@method'],
            signatureLabel: 'sig8',
            additionalParams: { keyid: 'sign-error-test', created: nowInSeconds },
            request,
            sign: async ({ err }) => err({ type: 'signing', message: 'Signing failed' }),
        });

        assert.deepStrictEqual(result, err({
            type: 'signing',
            message: 'Signing failed',
        }));
    });

    it('should return an error if the sign promise rejects', async () => {
        const request = {
            headers: new Headers(),
            url: new URL('https://example.com/foo'),
            method: 'POST',
            body: null,
        };

        const nowInSeconds = Math.floor(Date.now() / 1000);

        const result = await createSignatureForRequest({
            signatureInputs: ['@method'],
            signatureLabel: 'sig9',
            additionalParams: { keyid: 'sign-reject-test', created: nowInSeconds },
            request,
            sign: async () => Promise.reject(new Error('Promise rejected during signing')),
        });

        assert.deepStrictEqual(result, err({
            type: 'error',
            message: 'Failed to sign request',
            context: new Error('Promise rejected during signing'),
        }));
    });
});
