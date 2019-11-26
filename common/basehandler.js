const log4js = require("log4js");
const log = log4js.getLogger();
const rh = require("./responsehandler");

module.exports = class BaseHandler {
    //functionName - name of the subclass function
    constructor() {
        log.level = process.env.INFO;
        this.log = log;
    }
    // function to be overriden in subclass
    async process(event, context, callback) {
        this.log.debug('base class function');
    };

    //instantiating base with subclass tag
    async handler(event, context, callback) {
        this.log.info("Inside BaseHandler", JSON.stringify(event));
       
        context.callbackWaitsForEmptyEventLoop = false;
        try {
            this.log.info("Inside BaseHandler");
            //calling process function of class instantiated
            let response = await this.process(event, context, callback);
            if (response) {
                this.log.info("Process complete!:", response.body);
            }
            return response;
        } catch (e) {
            console.log("Inside base handler error", e);
            if('statusCode' in e && e.statusCode){
                return rh.callbackRespondWithSimpleMessage(e.statusCode, e.message);
            } 
            else {
                return rh.callbackRespondWithSimpleMessage(500, e.message);
            }
        }
    }
};