// Function to connect skyflow vault to Segpay PSP where they require the fields to be sent in a xml string inside a field called XMLData as x-www-form-urlencoded request body
// So we need to parse the string from the invoke connection request via a xml parser, extract the fields which needs to be detokenized, replace the tokenized values in the xml string and send request to psp

const axios = require('axios');
const xml2js = require('xml2js');
const { generateBearerTokenFromCreds } = require("skyflow-node");

exports.skyflowmain = async (event) => {
    const request = Buffer.from(event.BodyContent, 'base64');
    const headers = event.Headers;
    const requestId = headers?.['X-Request-Id']?.[0];

    // HTTP_Template response object for function which needs to be returned by the function in every case even during errors
    let functionResponse = {
        bodyBytes: "",  // This will contain the response body to be returned by the funtion
        headers: {
            "Content-Type": "application/json",  // This will contain the response content-type to be returned by the function
            "Error-From-Client": "false",  // This will be an extra header returned in response headers to help determine whether error came from third party PSP or not
        },
        statusCode: 200,   // This will contain the http response code to be returned by the function
    };

    try {
        if (request && request != '') {
            const encodedRequest = request?.toString('utf-8');
            const decodedRequest = decodeURIComponent(encodedRequest);
            const params = new URLSearchParams(decodedRequest);

            const xmlData = params.get('XMLData');
            if (!xmlData) {
                throw new Error('XMLData field not found in the request');
            }

            // For security reasons to avoid any xxe attacks
            const parser = new xml2js.Parser({
                explicitArray: false,  // Avoid wrapping single values in an array
                disableEntities: true, // Disable XML entity parsing
                doctype: null          // Optionally disable DTD parsing
            });

            // Parse the XML string
            const parsedXml = await parser.parseStringPromise(xmlData);

            // Extract the tokens
            const authRequest = parsedXml.data.authrequest;
            const cardNumberToken = authRequest.$.CardNumber;
            const cvvToken = authRequest.$.CVV;
            const expDateToken = authRequest.$.ExpDate;

            // Detokenize the fields
            const detokenizeResponse = await getDetokenizedFields(
                requestId,
                cardNumberToken,
                cvvToken,
                expDateToken
            );

            if (!detokenizeResponse.success) {
                functionResponse.bodyBytes = JSON.stringify(detokenizeResponse);
                functionResponse.statusCode = 500;
                return functionResponse;
            } else {
                // Replace tokens with detokenized values
                authRequest.$.CardNumber = detokenizeResponse.cardNumber;
                authRequest.$.CVV = detokenizeResponse.cvv;
                authRequest.$.ExpDate = detokenizeResponse.expDate;
            }

            // Convert the modified XML object back to string
            const builder = new xml2js.Builder();
            const modifiedXmlData = builder.buildObject(parsedXml);

            // Update the XMLData field in params
            params.set('XMLData', modifiedXmlData);

            const authUrl = process.env.authUrl;
            await axios
                .post(authUrl, params.toString(), {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    responseType: 'text',
                })
                .then((response) => {
                    functionResponse.bodyBytes = response.data;
                    functionResponse.headers['Content-Type'] = 'text/xml';
                    functionResponse.statusCode = response.status;
                })
                .catch((error) => {
                    functionResponse.bodyBytes = error?.response?.data;
                    functionResponse.headers['Content-Type'] = 'text/xml';
                    functionResponse.statusCode = error?.response?.status;
                    functionResponse.headers['Error-From-Client'] = 'true';
                });
        } else {
            functionResponse.bodyBytes = 'Bad request';
            functionResponse.statusCode = 400;
        }
    } catch (error) {
        functionResponse.bodyBytes = JSON.stringify(error?.message);
        functionResponse.statusCode = 500;
    } finally {
        return functionResponse;
    }
};

/**
 * Detokenizes Skyflow tokens
 * @param {string} requestId
 * @param {string} tokenizedCardNumber
 * @param {string} tokenizedCvv
 * @param {string} tokenizedExpDate
 * @returns { cardNumber: string, cvv: string, expDate: string, success: boolean }
 */
const getDetokenizedFields = async (requestId, tokenizedCardNumber, tokenizedCvv, tokenizedExpDate) => {
    const { credentials, vaultID, vaultURL } = process.env;
    const token = await generateBearerTokenFromCreds(credentials);
    const endpoint = `${vaultURL}/v1/vaults/${vaultID}/detokenize`;
    const fields = [tokenizedCardNumber, tokenizedCvv, tokenizedExpDate];
    const detokenizationParameters = fields.map(t => ({ token: t, redaction: 'PLAIN_TEXT' }));

    try {
        const response = await axios.post(
            endpoint,
            {
                detokenizationParameters,
                downloadURL: false,
            },
            {
                headers: {
                    'x-request-id': requestId,
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token?.accessToken}`,
                },
            }
        );

        return {
            // Replace the fields as you want
            cardNumber: response.data.records[0].value,
            cvv: response.data.records[1].value,
            expDate: response.data.records[2].value,
            success: true,
        };
    } catch (error) {
        return { success: false, error: error?.response?.data };
    }
};
