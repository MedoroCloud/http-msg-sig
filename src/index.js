import { decodeDict, Item, encodeItem, encodeDict } from 'structured-field-values';
import { Result, ResultAsync, err, ok } from 'neverthrow';

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
 * @param {function({signatureBase: string, params: Object.<string, unknown>, ok: import("neverthrow").ok, err: import("neverthrow").err}): Promise<import("neverthrow").Result<ArrayBuffer, {type: string, message: string, context?: unknown}>>} params.sign - An asynchronous function that signs the signature base. It takes an object with `signatureBase`, `params`, `ok` (neverthrow's `ok` function), and `err` (neverthrow's `err` function) and returns a Promise resolving to a `neverthrow.Result` where `Ok` is `ArrayBuffer` and `Err` is an error object.
 * @returns {Promise<import("neverthrow").Result<{signatureInput: string, signature: string, signatureBase: string}, {type: string, message: string, context?: unknown}>>} A Promise that resolves to a `neverthrow.Result`. If successful (`Ok`), it contains an object with `signatureInput`, `signature`, and `signatureBase` (all strings). If an error occurs (`Err`), it contains an object with `type`, `message`, and an optional `context`.
 */
export async function createSignatureForRequest({
    signatureInputs,
    signatureLabel,
    additionalParams,
    request: { headers, url, method },
    sign,
}) {
    // Create the signature input value - a list of component identifiers
    const signatureInputValue = signatureInputs.map(input => typeof input === 'string' ? new Item(input, {}) : new Item(input.component, input.parameters));

    // Create the signature input dictionary
    const signatureInputDictItem = new Item(signatureInputValue, additionalParams);
    const resultOfStringOfSignatureInputDictionary = Result.fromThrowable(
        () => encodeDict({ [signatureLabel]: signatureInputDictItem }),
        (error) => ({
            type: 'encoding',
            message: 'Failed to encode signature input dictionary',
            context: error
        })
    )();
    if (resultOfStringOfSignatureInputDictionary.isErr()) {
        return err(resultOfStringOfSignatureInputDictionary.error);
    }

    // Calculate signature base
    /** @type {[string, string][]} */
    const signatureBasePairResults = [];
    for (const inputName of signatureInputs) {
        const item = typeof inputName === 'string' ? new Item(inputName, {}) : new Item(inputName.component, inputName.parameters);
        const resultOfStringOfKey = Result.fromThrowable(
            () => encodeItem(item),
            (error) => ({
                type: 'encoding',
                message: 'Failed to encode signature input key',
                context: error
            })
        )();
        if (resultOfStringOfKey.isErr()) {
            return err(resultOfStringOfKey.error);
        }
        const stringOfKey = resultOfStringOfKey.value;

        switch (item.value) {
            case '@method': {
                signatureBasePairResults.push([stringOfKey, method]);
                break;
            }
            case '@target-uri': {
                signatureBasePairResults.push([stringOfKey, url.toString()]);
                break;
            }
            case '@authority': {
                signatureBasePairResults.push([stringOfKey, url.hostname]);
                break;
            }
            case '@scheme': {
                signatureBasePairResults.push([stringOfKey, url.protocol.slice(0, -1)]);
                break;
            }
            case '@path': {
                signatureBasePairResults.push([stringOfKey, url.pathname]);
                break;
            }
            case '@query': {
                signatureBasePairResults.push([stringOfKey, url.search.length > 0 ? url.search : '']);
                break;
            }
            case '@query-param': {
                const name = item.params instanceof Map ? item.params.get('name') : item.params?.name;
                if (!name) {
                    return err({
                        type: 'validation',
                        message: 'Invalid signature input',
                        context: 'Signature input is missing required parameter "name" in signature input for field ' + stringOfKey
                    });
                }
                const value = url.searchParams.get(name);
                if (value === null) {
                    return err({
                        type: 'validation',
                        message: 'Missing query parameter: ' + name,
                        context: 'Request is missing query parameter "' + name + '" required in signature input for field ' + stringOfKey
                    });
                }
                signatureBasePairResults.push([stringOfKey, value]);
                break;
            }
            default: {
                const value = headers.get(item.value);
                if (value === null) {
                    return err({
                        type: 'validation',
                        message: 'Missing header: ' + item.value,
                        context: 'Request is missing header "' + item.value + '" required in signature input for field ' + stringOfKey
                    });
                }
                signatureBasePairResults.push([stringOfKey, value]);
                break;
            }
        }
    }
    // Append @signature-params pair
    // remove [signatureLabel=] from stringOfSignatureInputDictionary
    signatureBasePairResults.push([encodeItem(new Item('@signature-params', {})), resultOfStringOfSignatureInputDictionary.value.slice(signatureLabel.length + 1)]);

    const signatureBase = signatureBasePairResults.map((pair) => pair.join(': ')).join('\n');

    // Sign the signature base
    const resultOfSignature = await ResultAsync.fromPromise(
        sign({ signatureBase, params: additionalParams, ok, err }),
        (error) => ({
            type: 'error',
            message: 'Failed to sign request',
            context: error
        })
    );

    if (resultOfSignature.isErr()) {
        return err(resultOfSignature.error);
    }

    if (resultOfSignature.value.isErr()) {
        return err(resultOfSignature.value.error);
    }

    const signature = resultOfSignature.value.value;
    const resultOfSignatureUint8Array = Result.fromThrowable(
        () => new Uint8Array(signature),
        (error) => ({
            type: 'encoding',
            message: 'Invalid data in provided signature. Failed to create signature Uint8Array',
            context: error
        })
    )();
    if (resultOfSignatureUint8Array.isErr()) {
        return err(resultOfSignatureUint8Array.error);
    }
    // Encode the signature dictionary - we use individual item encoding for compatibility
    const resultOfStringOfSignatureDictionary = Result.fromThrowable(
        () => encodeDict({ [signatureLabel]: new Item(resultOfSignatureUint8Array.value) }),
        (error) => ({
            type: 'encoding',
            message: 'Failed to encode signature dictionary',
            context: error
        })
    )();
    if (resultOfStringOfSignatureDictionary.isErr()) {
        return err(resultOfStringOfSignatureDictionary.error);
    }

    return ok({
        signatureInput: resultOfStringOfSignatureInputDictionary.value,
        signature: resultOfStringOfSignatureDictionary.value,
        signatureBase,
    });
}

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
export async function verifySignatureOfRequest({
    stringOfSignatureInputDictionary,
    stringOfSignatureDictionary,
    signatureLabel,
    requiredInputs,
    requiredParams,
    maxAge,
    request: { headers, url, method, body },
    verify,
}) {
    const resultOfSignatureInputDict = Result.fromThrowable(
        () => decodeDict(stringOfSignatureInputDictionary),
        (error) => ({
            type: 'validation',
            message: 'Invalid signature input',
            context: error
        })
    )();
    if (resultOfSignatureInputDict.isErr()) {
        return err(resultOfSignatureInputDict.error);
    }

    const signatureInputDict = resultOfSignatureInputDict.value;
    // signatureInputDict must be a Map or an object
    if (!(signatureInputDict instanceof Map) && !(signatureLabel in signatureInputDict)) {
        return err({
            type: 'validation',
            message: 'Invalid signature input',
            context: `Signature Input is not a dictionary or does not contain "${signatureLabel}" field`
        });
    }
    const signatureInputDictItem = signatureInputDict instanceof Map ? signatureInputDict.get(signatureLabel) : signatureInputDict[signatureLabel];
    if (!(signatureInputDictItem instanceof Item) || !Array.isArray(signatureInputDictItem.value) || signatureInputDictItem.value.length < 1) {
        return err({
            type: 'validation',
            message: 'Invalid signature input',
            context: `Invalid signature input for "${signatureLabel}"`
        });
    }

    for (const item of signatureInputDictItem.value) {
        if (!(item instanceof Item) || !(typeof item.value === 'string')) {
            return err({
                type: 'validation',
                message: 'Invalid signature input',
                context: 'Invalid signature input'
            });
        }
    }
    /** @type {Item[]} */
    const signatureInput = signatureInputDictItem.value;

    const resultOfSignatureDict = Result.fromThrowable(
        () => decodeDict(stringOfSignatureDictionary),
        (error) => ({
            type: 'validation',
            message: 'Invalid signature',
            context: error
        })
    )();
    if (resultOfSignatureDict.isErr()) {
        return err(resultOfSignatureDict.error);
    }

    const signatureDict = resultOfSignatureDict.value;

    // signatureDict must be a Map or an object
    if (!(signatureDict instanceof Map) && !(signatureLabel in signatureDict)) {
        return err({
            type: 'validation',
            message: 'Invalid signature',
            context: `Signature is not a dictionary or does not contain "${signatureLabel}" field`
        });
    }
    const signatureDictValue = signatureDict instanceof Map ? signatureDict.get(signatureLabel) : signatureDict[signatureLabel];
    if (!(signatureDictValue instanceof Item) || !(signatureDictValue.value instanceof Uint8Array)) {
        return err({
            type: 'validation',
            message: 'Invalid signature',
            context: 'Invalid signature'
        });
    }

    const providedSignature = signatureDictValue.value;

    // verify that all of the required inputs are present in signatureInput
    for (const input of requiredInputs) {
        const inputItem = typeof input === 'string' ?
            signatureInput.find((item) => item.value === input) :
            signatureInput.find((item) => item.value === input.component && Object.entries(input.parameters).every(([key, value]) => item.params instanceof Map ? item.params.get(key) === value : item.params[key] === value));
        if (!inputItem) {
            return err({
                type: 'validation',
                message: 'Invalid signature',
                context: `Missing required input field "${input}" in signature input`
            });
        }
    }

    // verify that all of the required params are present in signature input dictionary item
    const signatureInputParams = Object.fromEntries(Object.entries(signatureInputDictItem.params));
    for (const requiredParam of requiredParams) {
        if (!(requiredParam in signatureInputParams)) {
            return err({
                type: 'validation',
                message: 'Invalid signature',
                context: `Missing required parameter "${requiredParam}" in signature input`
            });
        }
    }

    // verify that the signature is not expired
    const paramCreated = signatureInputParams['created'];
    if (!paramCreated) {
        return err({
            type: 'validation',
            message: 'Invalid signature',
            context: 'Missing required parameter "created" in signature input'
        });
    }
    if (typeof paramCreated !== 'number') {
        return err({
            type: 'validation',
            message: 'Invalid signature',
            context: 'Invalid parameter "created" in signature input'
        });
    }
    const nowInSeconds = Date.now() / 1000;
    if ((nowInSeconds - paramCreated) > maxAge) {
        return err({
            type: 'validation',
            message: 'Signature expired',
            context: 'Signature expired'
        });
    }

    // check if signature inputs include content-digest
    const paramContentDigest = signatureInput.find((item) => item.value === 'content-digest');
    if (paramContentDigest) {
        // calculate content digest
        const headerValueForContentDigest = headers.get('content-digest');
        if (headerValueForContentDigest === null) {
            return err({
                type: 'validation',
                message: 'Invalid signature',
                context: 'Missing required header "content-digest"'
            });
        }

        const dictionaryOfContentDigest = Result.fromThrowable(
            () => decodeDict(headerValueForContentDigest),
            (error) => ({
                type: 'validation',
                message: 'Invalid value for header "content-digest"',
                context: error
            })
        )();
        if (dictionaryOfContentDigest.isErr()) {
            return err(dictionaryOfContentDigest.error);
        }

        /** @type {{ [x: string]: Item | import("structured-field-values").InnerList }} */
        const dictionaryAsObject = dictionaryOfContentDigest.value instanceof Map ? Object.fromEntries(dictionaryOfContentDigest.value.entries()) : dictionaryOfContentDigest.value;

        const providedDigestAlgorithms = Object.keys(dictionaryAsObject);

        const allowedDigestAlgorithms = ['sha-256', 'sha-512'];

        if (!providedDigestAlgorithms.some((algorithm) => allowedDigestAlgorithms.includes(algorithm))) {
            return err({
                type: 'validation',
                message: `Unsupported content-digest algorithm: ${providedDigestAlgorithms.join(', ')}`,
                context: `Unsupported content-digest algorithm: ${providedDigestAlgorithms.join(', ')}`
            });
        }

        const firstProvidedAndAllowedDigest = Object.entries(dictionaryAsObject).find(([algorithm]) => allowedDigestAlgorithms.includes(algorithm));
        if (!firstProvidedAndAllowedDigest) {
            return err({
                type: 'validation',
                message: `Unsupported content-digest algorithm: ${providedDigestAlgorithms.join(', ')}`,
                context: `Unsupported content-digest algorithm: ${providedDigestAlgorithms.join(', ')}`
            });
        }
        const [algorithm, digestItem] = firstProvidedAndAllowedDigest;
        if (!(digestItem instanceof Item) || !(digestItem.value instanceof Uint8Array)) {
            return err({
                type: 'validation',
                message: `Invalid digest for algorithm ${algorithm}`,
                context: `Invalid digest for algorithm ${algorithm}`
            });
        }
        // calculate digest
        const resultOfDigest = await ResultAsync.fromPromise(
            crypto.subtle.digest(algorithm, body || new Uint8Array()),
            (error) => ({
                type: 'validation',
                message: `Failed to calculate digest for algorithm ${algorithm}`,
                context: error
            })
        );
        if (resultOfDigest.isErr()) {
            return err(resultOfDigest.error);
        }

        // compare digest
        const providedDigest = digestItem.value;
        const calculatedDigest = new Uint8Array(resultOfDigest.value);
        if (!areUint8ArraysEqual(providedDigest, calculatedDigest)) {
            return err({
                type: 'validation',
                message: `Digest mismatch for algorithm ${algorithm}. Expected ${uint8ArrayToBase64(providedDigest)}, got ${uint8ArrayToBase64(calculatedDigest)}`,
                context: `Digest mismatch for algorithm ${algorithm}. Expected ${uint8ArrayToBase64(providedDigest)}, got ${uint8ArrayToBase64(calculatedDigest)}`
            });
        }
    }


    // calculate signature base
    /** @type {[string, string][]} */
    const signatureBasePairResults = [];
    for (const item of signatureInput) {
        const resultOfStringOfKey = Result.fromThrowable(
            () => encodeItem(item),
            (error) => ({
                type: 'encoding',
                message: 'Failed to encode signature input key',
                context: error
            })
        )();
        if (resultOfStringOfKey.isErr()) {
            return err(resultOfStringOfKey.error);
        }
        const stringOfKey = resultOfStringOfKey.value;
        switch (item.value) {
            case '@method': {
                signatureBasePairResults.push([stringOfKey, method]);
                break;
            }
            case '@target-uri': {
                signatureBasePairResults.push([stringOfKey, url.toString()]);
                break;
            }
            case '@authority': {
                signatureBasePairResults.push([stringOfKey, url.hostname]);
                break;
            }
            case '@scheme': {
                signatureBasePairResults.push([stringOfKey, url.protocol.slice(0, -1)]);
                break;
            }
            case '@path': {
                signatureBasePairResults.push([stringOfKey, url.pathname]);
                break;
            }
            case '@query': {
                signatureBasePairResults.push([stringOfKey, url.search]);
                break;
            }
            case '@query-param': {
                const name = item.params instanceof Map ? item.params.get('name') : item.params?.name;
                if (!name) {
                    return err({
                        type: 'validation',
                        message: 'Invalid signature input',
                        context: 'Signature input is missing required parameter "name" in signature input for field ' + stringOfKey
                    });
                }
                const value = url.searchParams.get(name);
                if (value === null) {
                    return err({
                        type: 'validation',
                        message: 'Missing query parameter: ' + name,
                        context: 'Request is missing query parameter "' + name + '" required in signature input for field ' + stringOfKey
                    });
                }
                signatureBasePairResults.push([stringOfKey, value]);
                break;
            }
            default: {
                const value = headers.get(item.value);
                if (value === null) {
                    return err({
                        type: 'validation',
                        message: 'Missing header: ' + item.value,
                        context: 'Request is missing header "' + item.value + '" required in signature input for field ' + stringOfKey
                    });
                }
                signatureBasePairResults.push([stringOfKey, value]);
                break;
            }
        }
    }

    // append @signature-params pair
    const signatureParamsValue = stringOfSignatureInputDictionary.split('=').slice(1).join('=');
    signatureBasePairResults.push([encodeItem(new Item('@signature-params')), signatureParamsValue]);

    const signatureBase = signatureBasePairResults.map((result) => result.join(': ')).join('\n');

    const resultOfVerification = await ResultAsync.fromPromise(
        verify({ signatureBase, params: signatureInputParams, signature: providedSignature, ok, err }),
        (error) => ({
            type: 'validation',
            message: 'Signature verification didn\'t pass',
            context: error
        })
    )
    if (resultOfVerification.isErr()) {
        return err(resultOfVerification.error);
    }
    if (resultOfVerification.value.isErr()) {
        return resultOfVerification.value;
    }

    return ok(resultOfVerification.value.value);
}

/**
 * Compares two Uint8Arrays for equality.
 *
 * @param {Uint8Array} a - The first Uint8Array.
 * @param {Uint8Array} b - The second Uint8Array.
 * @returns {boolean} True if the arrays are equal, false otherwise.
 */
function areUint8ArraysEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

/**
 * Converts a Uint8Array to a Base64 string.
 *
 * @param {Uint8Array} uint8Array - The Uint8Array to convert.
 * @returns {string} The Base64 encoded string.
 */
function uint8ArrayToBase64(uint8Array) {
    // Convert Uint8Array to a binary string
    const binaryString = String.fromCharCode(...uint8Array);
    // Encode the binary string to Base64
    return btoa(binaryString);
}
