// Function to connect skyflow vault to Azul PSP which requires MTLS and which requires passing expiration date as 1 field but user has expiration month and year in separate columns
// You will need to pass the mtls cert and mtls key as headers to the invoke connection request
// Skyflow specific env vars - credentials.json content as string, vaultID and vaultURL
// Psp specific env vars - pspUrl (psp endpoint)
// Other Authorization parameters like Auth1 and Auth2, required by psp are directly being passed in invoke connection request headers which we are extracting and passing it to psp request

const axios = require("axios");
const https = require('https');
const { generateBearerTokenFromCreds } = require("skyflow-node");

const skyflowmain = async (event) => {
    const request = Buffer.from(event.BodyContent, "base64");
    const headers = event.Headers;
    const requestId = headers?.["X-Request-Id"]?.[0];
    // client certificate and key required for mtls with azul psp via headers
    const certString = headers?.['Cert']?.[0];
    const keyString = headers?.['Key']?.[0];

    // Extract other authorization headers required by psp from the invoke connection request
    const Auth1 = headers?.['Auth1']?.[0];
    const Auth2 = headers?.['Auth2']?.[0];

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
        // Extract the environment variables
        const { credentials, vaultID, vaultURL, pspUrl } = process.env;

        if (request && request != "") {
            const payload = JSON.parse(request);
            // check if client certificate and key are provided in headers or not
            if (!certString || !keyString) {
                functionResponse.bodyBytes = "Bad request. Required headers 'cert' and 'key' for MTLS with Azul are missing.";
                functionResponse.statusCode = 400;
            }
            const cert = JSON.parse(`"${certString}"`);
            const key = JSON.parse(`"${keyString}"`);

            // Detokenize the fields in the payload which are tokenized
            const detokenizeResponse = await getDetokenizedFields(
                [payload.CardNumber, payload.ExpirationYear, payload.ExpirationMonth, payload.CVC],
                credentials,
                vaultURL,
                vaultID,
                requestId
            );
            if (detokenizeResponse?.success) {
                // Replace tokens with detokenized values
                payload.CardNumber = detokenizeResponse.CardNumber;
                payload.CVC = detokenizeResponse.CVC;
                delete payload.ExpirationMonth;
                delete payload.ExpirationYear;
                // Combine ExpiartionMonth and ExpirationYear in YYYYMM format and put it into Expiration field
                payload.Expiration = `20${detokenizeResponse.ExpirationYear}${detokenizeResponse.ExpirationMonth}`;

                const options = {
                    url: pspUrl,
                    headers: {
                        // Add required headers
                        'Auth1': Auth1,
                        'Auth2': Auth2,
                        'Content-Type': 'application/json',
                    },
                    method: 'POST',
                    data: payload,
                    httpsAgent: new https.Agent({
                        // Add client certificate and key from headers to httpsAgent for mtls
                        cert: cert,
                        key: key
                    })
                }

                // execute request
                await axios(options)
                    .then((response) => {
                        functionResponse.bodyBytes = JSON.stringify(response.data); // add the response here.
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
                CardNumber: response.data.records[0].value,
                ExpirationYear: response.data.records[1].value,
                ExpirationMonth: response.data.records[2].value,
                CVC: response.data.records[3].value,
                success: true,
            };
        })
        .catch((error) => {
            return error?.response?.data;
        });
    return apiResponse;
};

exports.skyflowmain = skyflowmain;