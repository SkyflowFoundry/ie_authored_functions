# Functions authored by IE team
A repository to store and maintain the functions authored by IE team


### A sample function template can be found here:
https://docs.skyflow-preview.com/functions-best-practices/#authoring


### Functions which are already on the docsite:
1. Age verification function: https://docs.skyflow-preview.com/functions-catalog-age-verification/#function-code

2. Docusign function: https://docs.skyflow-preview.com/functions-catalog-docusign-upload/#function-code

3. Interswitch function: https://docs.skyflow-preview.com/functions-catalog-auth-interswitch/#function-code

4. Platron function: https://docs.skyflow-preview.com/functions-catalog-auth-platron/#function-code



### Functions inside the repository:

1. Azul function:
Need - Azul psp requires expiration date to be sent as a single field whereas user has two separate columns for expiration month and year. It also demonstrate how to connect to psp which requires MTLS via a function.

2. Cybersource function:
Need - Cybersource psp requires an http signature to be sent in request body which needs to be generated on the detokenized request payload.

3. Segpay function:
Need - Segpay psp requires the fields to be sent in an xml format but the xml is wrapped as a string value in a field called XMLData inside a x-www-form-urlencoded content-type request body.
