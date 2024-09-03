// Function to connect skyflow vault to Cybersource PSP which requires a HTTP signature
// Skyflow specific env variables used are credentials.json content, vaultID and vaultURL
// Cybersource specific env variables used are merchantSecretKey, merchantKeyId, merchantId, requestHost(request domain) and resourcePath(request path/route)

const axios = require("axios");
const crypto = require('crypto');
const { generateBearerTokenFromCreds } = require("skyflow-node");

const skyflowmain = async (event) => {
    const request = Buffer.from(event.BodyContent, "base64");
    const headers = event.Headers;
    const requestId = headers?.["X-Request-Id"]?.[0];

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
        // Extracting the environment variables
        const { credentials, vaultID, vaultURL, merchantSecretKey, merchantKeyId, merchantId, resourcePath, requestHost } = process.env;

        if (request && request != "") {
            const payload = JSON.parse(request);
            // Detokenize the fields in the payload which are tokenized
            const detokenizeResponse = await getDetokenizedFields(
                [payload.paymentInformation.card.number, payload.paymentInformation.card.expirationMonth, payload.paymentInformation.card.expirationYear],
                credentials,
                vaultURL,
                vaultID,
                requestId
            );
            if (detokenizeResponse?.success) {
                // Perfom psp specific operations here
                // Replace tokens with detokenized values
                payload.paymentInformation.card.number = detokenizeResponse.card_number;
                payload.paymentInformation.card.expirationMonth = detokenizeResponse.expiry_month;
                payload.paymentInformation.card.expirationYear = detokenizeResponse.expiry_year;

                let getDigest = generateDigest(payload);
                const gmtDateTime = getGMTDateTime();

                const sig = getHttpSignature(resourcePath, requestHost, merchantSecretKey, merchantKeyId, merchantId, getDigest, gmtDateTime);

                getDigest = "SHA-256=" + getDigest;

                // Construct the payload and call the PSP
                const pspUrl = 'https://' + requestHost + resourcePath;
                await axios
                    .post(pspUrl, payload, {
                        headers: {
                            // Add required headers
                            'host': requestHost,
                            'Content-Type': 'application/json',
                            'v-c-merchant-id': merchantId,
                            'date': gmtDateTime,
                            'signature': sig,
                            'digest': getDigest
                        },
                    })
                    .then((response) => {
                        functionResponse.bodyBytes = JSON.stringify(response.data); // Add the response here which needs to be returned as function response.
                    })
                    .catch((error) => {
                        functionResponse.bodyBytes = JSON.stringify(error?.response?.data);
                        functionResponse.statusCode = error?.response?.status;
                        functionResponse.headers["Error-From-Client"] = "true";
                    });
            } else {
                functionResponse.bodyBytes = JSON.stringify(detokenizeResponse);
                functionResponse.statusCode = detokenizeResponse?.error?.http_code;
            }
        } else {
            functionResponse.bodyBytes = "Bad request";
            functionResponse.statusCode = 400;
        }
    } catch (error) {
        functionResponse.bodyBytes = JSON.stringify(error?.message);
        functionResponse.statusCode = 500;
    } finally {
        return functionResponse;
    }
};

function getGMTDateTime() {
    const now = new Date();
    const gmtDateTime = now.toUTCString();
    return gmtDateTime;
}

const getDetokenizedFields = async (
    fields,
    credentials,
    vaultURL,
    vaultID,
    requestId
) => {
    const endpoint = vaultURL + "/v1/vaults/" + vaultID + "/" + "detokenize";
    let detokenizationParameters = [];
    fields.forEach((element) => {
        if (element) {
            detokenizationParameters.push({
                token: element,
                redaction: "PLAIN_TEXT",
            });
        }
    });
    const token = await generateBearerTokenFromCreds(credentials);
    const apiResponse = await axios
        .post(
            endpoint,
            {
                detokenizationParameters: detokenizationParameters,
                downloadURL: false,
            },
            {
                headers: {
                    "x-request-id": requestId,
                    "Content-Type": "application/json",
                    Authorization: "Bearer " + token?.accessToken,
                },
            }
        )
        .then((response) => {
            return {
                // Replace the fields as you want
                card_number: response.data.records[0].value,
                expiry_month: response.data.records[1].value,
                expiry_year: response.data.records[2].value,
                success: true,
            };
        })
        .catch((error) => {
            return error?.response?.data;
        });
    return apiResponse;
};

function generateDigest(payload) {
    let digest = "DIGEST_PLACEHOLDER";

    try {
        const payloadString = JSON.stringify(payload);
        let buffer = Buffer.from(payloadString, 'utf8');
        const hash = crypto.createHash('sha256');
        hash.update(buffer);
        digest = hash.digest('base64');
    } catch (error) {
        console.log("ERROR generating digest : " + error.toString());
    }

    return digest;
}

function getHttpSignature(resourcePath, requestHost, merchantSecretKey, merchantKeyId, merchantId, getDigest, gmtDateTime) {
    var signatureHeader = "";
    var signatureValue = "";

    signatureHeader += "keyid=\"" + merchantKeyId + "\"";

    signatureHeader += ", algorithm=\"HmacSHA256\"";

    var headersForPostMethod = "host date request-target digest v-c-merchant-id";
    signatureHeader += ", headers=\"" + headersForPostMethod + "\"";

    var signatureString = 'host: ' + requestHost;

    signatureString += '\ndate: ' + gmtDateTime;
    signatureString += '\nrequest-target: ';

    var digest = getDigest;

    var targetUrlForPost = "post " + resourcePath;
    signatureString += targetUrlForPost + '\n';

    signatureString += 'digest: SHA-256=' + digest + '\n';

    signatureString += 'v-c-merchant-id: ' + merchantId;

    var data = Buffer.from(signatureString, 'utf8');

    // Decoding secret key
    var key = Buffer.from(merchantSecretKey, 'base64');

    signatureValue = crypto.createHmac('sha256', key)
        .update(data)
        .digest('base64');

    signatureHeader += ", signature=\"" + signatureValue + "\"";

    return signatureHeader;
}

exports.skyflowmain = skyflowmain;
