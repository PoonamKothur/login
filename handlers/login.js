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
            TableName: `customer-${process.env.STAGE}`,
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

    //this function get userpool id by cuid
    async getResources(cuid) {
        console.log("in get resources");
        let name = `${cuid}-userpool`;
        console.log(name);

        var params = {
            TableName: `customer-resources-${process.env.STAGE}`,
            Key: {
                "name": name
            }
        };
        let valRes = await dynamodb.get(params).promise();
        console.log("response from get");
        //console.log(valRes.Item.attributes.poolid);
        if (valRes && 'Item' in valRes && valRes.Item && 'name' in valRes.Item && valRes.Item.name) {
            return valRes.Item.attributes.poolid;
        }
        else {
            return responseHandler.callbackRespondWithSimpleMessage(404, 'Userpool not created')
        }
    }
    //this function returns state of customer
    async getstate(event) {
        var params = {
            TableName: `${process.env.STAGE}-admin-customer-state`,
            Key: {
                "ip": event.requestContext.identity.sourceIp
            }
        };

        let getres = await dynamodb.get(params).promise();
        return getres;
    }

    //this function is for login
    async initiateAuth(authData) {
        try {
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
            let loginresp = await cognitoidentityserviceprovider.initiateAuth(params).promise();
            this.log.debug("loginresp", loginresp);
            console.log("loginresp", loginresp);
            return true;
        }
        catch (err) {
            console.log(err);
            if (err && 'statusCode' in err && err.statusCode) {
                if (err.statusCode === 400)
                    return false;
                else
                    return responseHandler.callbackRespondWithSimpleMessage(500, err.message);
            }
        }
    }

    // This method handles customer id
    async handleCustomerId(event) {
        console.log("in customer hadle");
        let body = JSON.parse(event.body);

        let customerExists = await this.checkIfCustomerExists(body.cuid);
        if (customerExists) {
            //Add state in admin-customer-state
            //{ip: <>, state: 'customerid', cuid: body.cuid}
            let stateresp = this.getstate(event);
            if (stateresp && 'cuid' in stateresp && stateresp.cuid && stateresp.cuid == body.cuid) {
                return;
            }

            const params = {
                TableName: `${process.env.STAGE}-admin-customer-state`,
                Item: {
                    "ip": event.requestContext.identity.sourceIp,
                    "state": 'customerid',
                    "cuid": body.cuid
                }
            };
            console.log(params);
            let valRes = await dynamodb.put(params).promise();
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
        let stateresp = await this.getstate(event);
        console.log(stateresp);
        // If state is present and state value is 'customerid'
        if (!(stateresp && 'state' in stateresp.Item && stateresp.Item.state && stateresp.Item.state === 'customerid')) {
            //console.log(stateresp.state);
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'no' });
        }
        // a. Get user pool details from customer resources table using cuid
        let userpoolid = await this.getResources(stateresp.Item.cuid);
        // b. Check if username is present in userpool
        let userpoolres = await this.checkUserExist(body.username, userpoolid);
        // c. if username is present then return yes
        // d. if username is not present then return no
        if (userpoolres) {
            // e. Update state // Add state in admin-customer-state
            // {ip: <>, state: 'username', cuid: body.cuid, username: body.username}
            const params = {
                TableName: `${process.env.STAGE}-admin-customer-state`,
                Item: {
                    "ip": event.requestContext.identity.sourceIp,
                    "state": 'username',
                    "cuid": stateresp.Item.cuid,
                    "username": body.username
                }
            };
            console.log(params);
            let valRes = await dynamodb.put(params).promise();
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'yes' });
        } else {
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'no' });
        }
    }

    // This method handles login 
    async handleLogin(event) {
        let body = JSON.parse(event.body);
        // Get last state using ip address from admin-customer-state
        // If state not present - return no

        let stateresp = await this.getstate(event);

        // If state is present and state value is 'username'
        if (!(stateresp && 'state' in stateresp.Item && stateresp.Item.state && stateresp.Item.state === 'username')) {
            //console.log(stateresp.state);
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'no' });
        }

        //get clientId from customer resources table
        let cuid = stateresp.Item.cuid;
        let name = `${cuid}-userpool`;
        let paramsres = {
            TableName: `customer-resources-${process.env.STAGE}`,
            Key: {
                "name": name
            }
        };
        let respresource = await dynamodb.get(paramsres).promise();
        console.log(respresource);
        let clientId = respresource.Item.attributes.clientid;
        console.log(clientId);

        // a.Check if login is correct
        // b. If login is correct -> return 'yes'
        let authData = {
            Username: stateresp.Item.username,
            Password: body.password,
            ClientId: clientId
        };

        let loginresp = await this.initiateAuth(authData);

        if (loginresp) {
            // c.  Update state // Add state in admin-customer-state
            // {ip: <>, state: 'login', cuid: body.cuid, username: body.username, password: body.password}
            // d. If login is not correct -> return 'no'
            const params = {
                TableName: `${process.env.STAGE}-admin-customer-state`,
                Item: {
                    "ip": event.requestContext.identity.sourceIp,
                    "state": 'login',
                    "cuid": stateresp.Item.cuid,
                    "username": stateresp.Item.username,
                    "password": "validationdone"
                }
            };
            console.log(params);
            let valRes = await dynamodb.put(params).promise();
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'yes' });
        } else {
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'no' });
        }
    }

    // This method handles mfa 
    async handleMFA(event) {
        let body = JSON.parse(event.body);
        // Get last state using ip address from admin-customer-state
        // If state not present - return no

        let stateresp = await this.getstate(event);
 
        // If state is present and state value is 'login'
        if (!(stateresp && 'state' in stateresp.Item && stateresp.Item.state && stateresp.Item.state === 'login')) {
            console.log(stateresp.state);
            return responseHandler.callbackRespondWithJsonBody(200, { result: 'no' });
        }

        // a.Check if login is correct with mfa
        // b. If login is correct -> return JWT (access token from cognito)
        // c. Delete state by ip
        // d. If login is not correct -> return 'no'
    }

    async process(event, context, callback) {
        try {

            let body = event.body ? JSON.parse(event.body) : event;
            //console.log(event.requestContext.identity.sourceIp);

            this.log.debug("body----" + JSON.stringify(event.body));
            //await utils.validate(body, this.getValidationSchema());

            // Scenario 1: Customer id is passed
            if ('cuid' in body && body.cuid) {
                return await this.handleCustomerId(event);

            } else if ('username' in body && body.username) {
                console.log("in username handle");
                return await this.handleUsername(event);

            } else if ('password' in body && body.password) {

                return await this.handleLogin(event);
            }
            // } else if ('mfa' in body) {
            //     return await this.handleMFA(event);
            // }

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
    console.log("in process");
    return await new Login().handler(event, context, callback);
};
