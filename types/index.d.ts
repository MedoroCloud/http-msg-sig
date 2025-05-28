/**
 * Creates a signature for a given HTTP request based on provided inputs and a signing function.
 * This function utilizes the `neverthrow` Result type for explicit error handling.
 *
 * @param {object} params - The parameters for creating the signature.
 * @param {(string|{component: '@query-param', parameters: { name: string }})[]} params.signatureInputs - An array of strings or objects with a `component` property and a `parameters` property, where `parameters` is a Map of string keys to string, number, or boolean values.
 * @param {string} params.signatureLabel - A label for the signature.
 * @param {Object.<string, (number|string)>} params.additionalParams - Additional parameters to include in the signature.
 * @param {object} params.request - The HTTP request object.
 * @param {Headers} params.request.headers - The request headers.
 * @param {URL} params.request.url - The request URL.
 * @param {string} params.request.method - The HTTP method (e.g., 'GET', 'POST').
 * @param {(ArrayBuffer|ArrayBufferView|null)=} params.request.body - The optional request body.
 * @param {function({signatureBase: string, params: Object.<string, unknown>, ok: import("neverthrow").ok, err: import("neverthrow").err}): Promise<import("neverthrow").Result<ArrayBuffer, {type: string, message: string, context?: unknown}>>} params.sign - An asynchronous function that signs the signature base. It takes an object with `signatureBase`, `params`, `ok` (neverthrow's `ok` function), and `err` (neverthrow's `err` function) and returns a Promise resolving to a `neverthrow.Result` where `Ok` is `ArrayBuffer` and `Err` is an error object.
 * @returns {Promise<import("neverthrow").Result<{signatureInput: string, signature: string, signatureBase: string}, {type: string, message: string, context?: unknown}>>} A Promise that resolves to a `neverthrow.Result`. If successful (`Ok`), it contains an object with `signatureInput`, `signature`, and `signatureBase` (all strings). If an error occurs (`Err`), it contains an object with `type`, `message`, and an optional `context`.
 */
export function createSignatureForRequest({ signatureInputs, signatureLabel, additionalParams, request: { headers, url, method, body }, sign, }: {
    signatureInputs: (string | {
        component: "@query-param";
        parameters: {
            name: string;
        };
    })[];
    signatureLabel: string;
    additionalParams: {
        [x: string]: (number | string);
    };
    request: {
        headers: Headers;
        url: URL;
        method: string;
        body?: (ArrayBuffer | ArrayBufferView | null) | undefined;
    };
    sign: (arg0: {
        signatureBase: string;
        params: {
            [x: string]: unknown;
        };
        ok: typeof ok;
        err: typeof err;
    }) => Promise<import("neverthrow").Result<ArrayBuffer, {
        type: string;
        message: string;
        context?: unknown;
    }>>;
}): Promise<import("neverthrow").Result<{
    signatureInput: string;
    signature: string;
    signatureBase: string;
}, {
    type: string;
    message: string;
    context?: unknown;
}>>;
/**
 * Verifies the signature of an HTTP request based on provided signature information and a verification function.
 * This function utilizes the `neverthrow` Result type for explicit error handling.
 *
 * @param {object} params - The parameters for verifying the signature.
 * @param {string} params.stringOfSignatureInputDictionary - The string representation of the signature input dictionary.
 * @param {string} params.stringOfSignatureDictionary - The string representation of the signature dictionary.
 * @param {string} params.signatureLabel - The label associated with the signature.
 * @param {(string|{component: '@query-param', parameters: { name: string }})[]} params.requiredInputs - An array of strings or objects with a `component` property and a `parameters` property, where `parameters` is a Map of string keys to string, number, or boolean values.
 * @param {string[]} params.requiredParams - An array of required parameters for the signature.
 * @param {number} params.maxAge - The maximum age (in seconds) for the signature to be considered valid.
 * @param {object} params.request - The HTTP request object.
 * @param {Headers} params.request.headers - The request headers.
 * @param {URL} params.request.url - The request URL.
 * @param {string} params.request.method - The HTTP method (e.g., 'GET', 'POST').
 * @param {(ArrayBuffer|ArrayBufferView|null)=} params.request.body - The optional request body.
 * @param {function({signatureBase: string, params: Object.<string, unknown>, signature: Uint8Array, ok: import("neverthrow").ok, err: import("neverthrow").err}): Promise<import("neverthrow").Result<true, {type: string, message: string, context?: unknown}>>} params.verify - An asynchronous function that verifies the signature. It takes an object with `signatureBase`, `params`, `signature` (as Uint8Array), `ok` (neverthrow's `ok` function), and `err` (neverthrow's `err` function) and returns a Promise resolving to a `neverthrow.Result` where `Ok` is `true` and `Err` is an error object.
 * @returns {Promise<import("neverthrow").Result<true, {type: string, message: string, context?: unknown}>>} A Promise that resolves to a `neverthrow.Result`. If successful (`Ok`), it contains `true`. If an error occurs (`Err`), it contains an object with `type`, `message`, and an optional `context`.
 */
export function verifySignatureOfRequest({ stringOfSignatureInputDictionary, stringOfSignatureDictionary, signatureLabel, requiredInputs, requiredParams, maxAge, request: { headers, url, method, body }, verify, }: {
    stringOfSignatureInputDictionary: string;
    stringOfSignatureDictionary: string;
    signatureLabel: string;
    requiredInputs: (string | {
        component: "@query-param";
        parameters: {
            name: string;
        };
    })[];
    requiredParams: string[];
    maxAge: number;
    request: {
        headers: Headers;
        url: URL;
        method: string;
        body?: (ArrayBuffer | ArrayBufferView | null) | undefined;
    };
    verify: (arg0: {
        signatureBase: string;
        params: {
            [x: string]: unknown;
        };
        signature: Uint8Array;
        ok: typeof ok;
        err: typeof err;
    }) => Promise<import("neverthrow").Result<true, {
        type: string;
        message: string;
        context?: unknown;
    }>>;
}): Promise<import("neverthrow").Result<true, {
    type: string;
    message: string;
    context?: unknown;
}>>;
import { ok } from 'neverthrow';
import { err } from 'neverthrow';
