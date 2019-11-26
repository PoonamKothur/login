const responseHandler = require("../common/responsehandler");
const BaseHandler = require("../common/basehandler");
const utils = require('../common/utils');
const Joi = require('joi');
const AWS = require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();
const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();

class Login extends BaseHandler {
    //this is main function
    constructor() {
        super();
    }

    //this function is for validation body
    getValidationSchema() {
        this.log.info('Inside getValidationSchema');
        return Joi.object().keys({
            cid: Joi.string(),
            username: Joi.string().email(),
            password: Joi.string(),
            mfa: Joi.string().valid(['2FA', '2SV'])
        });
    }

    // This function is used to get customer by cuid
    async checkIfCustomerExists(cuid) {
        let params = {
            TableName: `customers-${process.env.STAGE}`,
            KeyConditionExpression: "#cuid = :cuidValue",
            ExpressionAttributeNames: {
                "#cuid": "cuid"
            },
            ExpressionAttributeValues: {
                ":cuidValue": cuid
            }
        };

        this.log.debug("params---" + JSON.stringify(params));
        let valRes = await dynamodb.query(params).promise();
        this.log.debug("return values of table --- " + JSON.stringify(valRes));

        if (valRes && valRes.Count != 0) {
            this.log.debug("Customer exits");
            return true;
        }
        else {
            this.log.debug("Customer do not exits");
            return false;
        }
    }

    //this function is to get user by username and poolid
    async checkUserExist(username, userPoolId) {
        try {
            let params = {
                UserPoolId: userPoolId,
                /* required */
                Username: username
            };
            let respUser = await cognitoidentityserviceprovider.adminGetUser(params).promise();
            this.log.debug("respUser", respUser);
            return true;
        }
        catch (err) {
            if (err && 'statusCode' in err && err.statusCode) {

                if (err.statusCode === 400)
                    return false;
                else
                    return responseHandler.callbackRespondWithSimpleMessage(500, err.message);
            }
        }
    }

    //this function is for login
    async initiateAuth(authData) {
        let params = {
            AuthFlow: 'USER_PASSWORD_AUTH',
            /* required */
            ClientId: authData.ClientId,
            /* required */
            AuthParameters: {
                'USERNAME': authData.Username,
                'PASSWORD': authData.Password
            }
        };
        return await cognitoidentityserviceprovider.initiateAuth(params).promise();
    }

    // This method handles customer id
    async handleCustomerId(event) {
        let body = JSON.parse(event.body);
        let customerExists = await this.checkIfCustomerExists(body.cuid);
        if (customerExists) {
            // Add state in admin-customer-state
            // {ip: <>, state: 'customerid', cuid: body.cuid}

            return responseHandler.callbackRespondWithJsonBody(200, { result: 'yes' });
        } else {
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'no' });
        }
    }

    // This method handles username 
    async handleUsername(event) {
        let body = JSON.parse(event.body);
        // Get last state using ip address from admin-customer-state
        // If state not present - return no
        // If state is present and state value is 'customerid'
        // a. Get user pool details from customer resources table using cuid
        // b. Check if username is present in userpool
        // c. if username is present then return yes
        // d. if username is not present then return no
        // e. Update state // Add state in admin-customer-state
        // {ip: <>, state: 'username', cuid: body.cuid, username: body.username}
    }

    // This method handles login 
    async handleLogin(event) {
        let body = JSON.parse(event.body);
        // Get last state using ip address from admin-customer-state
        // If state not present - return no
        // If state is present and state value is 'username'
        // a.Check if login is correct
        // b. If login is correct -> return 'yes'
        // c.  Update state // Add state in admin-customer-state
        // {ip: <>, state: 'login', cuid: body.cuid, username: body.username, password: body.password}
        // d. If login is not correct -> return 'no'
    }

    // This method handles mfa 
    async handleMFA(event) {
        let body = JSON.parse(event.body);
        // Get last state using ip address from admin-customer-state
        // If state not present - return no
        // If state is present and state value is 'login'
        // a.Check if login is correct with mfa
        // b. If login is correct -> return JWT (access token from cognito)
        // c. Delete state by ip
        // d. If login is not correct -> return 'no'
    }


    async process(event, context, callback) {
        try {

            let body = event.body ? JSON.parse(event.body) : event;
            this.log.debug("body----" + JSON.stringify(event.body));
            await utils.validate(body, this.getValidationSchema());


            // Scenario 1: Customer id is passed
            if ('cuid' in body && body.cuid) {
                return await this.handleCustomerId(event);
            } else if ('username' in body && body.username) {
                return await this.handleUsername(event);
            } else if ('password' in body && body.password) {
                return await this.handleLogin(event);
            } else if ('mfa' in body) {
                return await this.handleMFA(event);
            }

            return responseHandler.callbackRespondWithSimpleMessage(400, 'Invalid input');

        }
        catch (err) {
            if (err.message) {
                return responseHandler.callbackRespondWithSimpleMessage(400, err.message);
            }
            else {
                return responseHandler.callbackRespondWithSimpleMessage(500, 'Internal Server Error');
            }
        }
    }
}

exports.login = async (event, context, callback) => {
    return await new Login().handler(event, context, callback);
};
