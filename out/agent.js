"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const debug_1 = __importDefault(require("debug"));
const url_1 = require("url");
const http_proxy_agent_1 = require("http-proxy-agent");
const https_proxy_agent_1 = require("https-proxy-agent");
const socks_proxy_agent_1 = require("socks-proxy-agent");
const agent_base_1 = require("agent-base");
const events_1 = __importDefault(require("events"));
const debug = (0, debug_1.default)('pac-proxy-agent');
/**
 * The `PacProxyAgent` class.
 *
 * A few different "protocol" modes are supported (supported protocols are
 * backed by the `get-uri` module):
 *
 *   - "pac+data", "data" - refers to an embedded "data:" URI
 *   - "pac+file", "file" - refers to a local file
 *   - "pac+ftp", "ftp" - refers to a file located on an FTP server
 *   - "pac+http", "http" - refers to an HTTP endpoint
 *   - "pac+https", "https" - refers to an HTTPS endpoint
 *
 * @api public
 */
class _PacProxyAgent extends agent_base_1.Agent {
    constructor(resolver, opts = {}) {
        super(opts);
        debug('Creating PacProxyAgent with options %o', opts);
        this.resolver = resolver;
        this.opts = Object.assign({}, opts);
        this.cache = undefined;
    }
    /**
     * Called when the node-core HTTP client library is creating a new HTTP request.
     *
     * @api protected
     */
    connect(req, opts) {
        return __awaiter(this, void 0, void 0, function* () {
            const { secureEndpoint } = opts;
            // Calculate the `url` parameter
            const defaultPort = secureEndpoint ? 443 : 80;
            let path = req.path;
            let search = null;
            const firstQuestion = path.indexOf('?');
            if (firstQuestion !== -1) {
                search = path.substring(firstQuestion);
                path = path.substring(0, firstQuestion);
            }
            const urlOpts = Object.assign(Object.assign({}, opts), { protocol: secureEndpoint ? 'https:' : 'http:', pathname: path, search, 
                // need to use `hostname` instead of `host` otherwise `port` is ignored
                hostname: opts.host, host: null, href: null, 
                // set `port` to null when it is the protocol default port (80 / 443)
                port: defaultPort === opts.port ? null : opts.port });
            const url = (0, url_1.format)(urlOpts);
            debug('url: %o', url);
            let result = yield this.resolver(req, opts, url);
            // Default to "DIRECT" if a falsey value was returned (or nothing)
            if (!result) {
                result = 'DIRECT';
            }
            const proxies = String(result)
                .trim()
                .split(/\s*;\s*/g)
                .filter(Boolean);
            if (this.opts.fallbackToDirect && !proxies.includes('DIRECT')) {
                proxies.push('DIRECT');
            }
            for (const proxy of proxies) {
                let agent = null;
                const [type, target] = proxy.split(/\s+/);
                debug('Attempting to use proxy: %o', proxy);
                if (type === 'DIRECT') {
                    // Needed for SNI.
                    const originalAgent = this.opts.originalAgent;
                    const defaultAgent = secureEndpoint ? https_1.default.globalAgent : http_1.default.globalAgent;
                    agent = originalAgent === false ? new defaultAgent.constructor() : (originalAgent || defaultAgent);
                }
                else if (type === 'SOCKS' || type === 'SOCKS5') {
                    // Use a SOCKSv5h proxy
                    agent = new socks_proxy_agent_1.SocksProxyAgent(`socks://${target}`);
                }
                else if (type === 'SOCKS4') {
                    // Use a SOCKSv4a proxy
                    agent = new socks_proxy_agent_1.SocksProxyAgent(`socks4a://${target}`);
                }
                else if (type === 'PROXY' ||
                    type === 'HTTP' ||
                    type === 'HTTPS') {
                    // Use an HTTP or HTTPS proxy
                    // http://dev.chromium.org/developers/design-documents/secure-web-proxy
                    const proxyURL = `${type === 'HTTPS' ? 'https' : 'http'}://${target}`;
                    if (secureEndpoint) {
                        agent = new HttpsProxyAgent2(proxyURL, this.opts);
                    }
                    else {
                        agent = new http_proxy_agent_1.HttpProxyAgent(proxyURL, this.opts);
                    }
                }
                try {
                    if (agent) {
                        let s;
                        if (agent instanceof agent_base_1.Agent) {
                            s = yield agent.connect(req, opts);
                        }
                        else {
                            s = agent;
                        }
                        req.emit('proxy', { proxy, socket: s });
                        return s;
                    }
                    throw new Error(`Could not determine proxy type for: ${proxy}`);
                }
                catch (err) {
                    debug('Got error for proxy %o: %o', proxy, err);
                    req.emit('proxy', { proxy, error: err });
                }
            }
            throw new Error(`Failed to establish a socket connection to proxies: ${JSON.stringify(proxies)}`);
        });
    }
}
class HttpsProxyAgent2 extends https_proxy_agent_1.HttpsProxyAgent {
    constructor(proxy, opts) {
        const addHeaders = {};
        const origHeaders = opts === null || opts === void 0 ? void 0 : opts.headers;
        const agentOpts = Object.assign(Object.assign({}, opts), { headers: () => {
                const headers = origHeaders
                    ? typeof origHeaders === 'function'
                        ? origHeaders()
                        : origHeaders
                    : {};
                return Object.assign(Object.assign({}, headers), addHeaders);
            } });
        super(proxy, agentOpts);
        this.addHeaders = addHeaders;
        this.lookupProxyAuthorization = opts.lookupProxyAuthorization;
    }
    connect(req, opts, state = {}) {
        const _super = Object.create(null, {
            connect: { get: () => super.connect }
        });
        return __awaiter(this, void 0, void 0, function* () {
            const tmpReq = new events_1.default();
            let connect;
            tmpReq.once('proxyConnect', (_connect) => {
                connect = _connect;
            });
            if (this.lookupProxyAuthorization && !this.addHeaders['Proxy-Authorization']) {
                try {
                    const proxyAuthorization = yield this.lookupProxyAuthorization(this.proxy.href, undefined, state);
                    if (proxyAuthorization) {
                        this.addHeaders['Proxy-Authorization'] = proxyAuthorization;
                    }
                }
                catch (err) {
                    req.emit('error', err);
                }
            }
            const s = yield _super.connect.call(this, tmpReq, opts);
            const proxyAuthenticate = connect === null || connect === void 0 ? void 0 : connect.headers['proxy-authenticate'];
            if (this.lookupProxyAuthorization && (connect === null || connect === void 0 ? void 0 : connect.statusCode) === 407 && proxyAuthenticate) {
                try {
                    const proxyAuthorization = yield this.lookupProxyAuthorization(this.proxy.href, proxyAuthenticate, state);
                    if (proxyAuthorization) {
                        this.addHeaders['Proxy-Authorization'] = proxyAuthorization;
                        tmpReq.removeAllListeners();
                        s.destroy();
                        return this.connect(req, opts, state);
                    }
                }
                catch (err) {
                    req.emit('error', err);
                }
            }
            req.once('socket', s => tmpReq.emit('socket', s));
            return s;
        });
    }
}
function createPacProxyAgent(resolver, opts) {
    if (!opts) {
        opts = {};
    }
    if (typeof resolver !== 'function') {
        throw new TypeError('a resolve function must be specified!');
    }
    return new _PacProxyAgent(resolver, opts);
}
(function (createPacProxyAgent) {
    createPacProxyAgent.PacProxyAgent = _PacProxyAgent;
    createPacProxyAgent.prototype = _PacProxyAgent.prototype;
})(createPacProxyAgent || (createPacProxyAgent = {}));
module.exports = createPacProxyAgent;
//# sourceMappingURL=agent.js.map