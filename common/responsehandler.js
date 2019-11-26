'use strict';

exports.callbackRespondWithCodeOnly = function (code) {
    return {
        statusCode: code,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": true,
            "Access-Control-Allow-Headers": "*"
        }
    };
};

exports.callbackRespondWithSimpleMessage = function (code, message) {
    return {
        statusCode: code,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": true,
            "Access-Control-Allow-Headers": "*"
        },
        body: JSON.stringify({
            message:message
        })
        
    };
};

exports.callbackRespondWithJsonBody = function (code, body) {
    return {
        statusCode: code,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": true,
            "Access-Control-Allow-Headers": "*"
        },
        body: JSON.stringify(body)
    };
};