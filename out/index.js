"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Nathan Rajlich, Félicien François, Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.toLogString = exports.resetCaches = exports.loadSystemCertificates = exports.getOrLoadAdditionalCertificates = exports.patchUndici = exports.setProxyAuthorizationHeader = exports.createWebSocketPatch = exports.createFetchPatch = exports.createTlsPatch = exports.createNetPatch = exports.createHttpPatch = exports.createProxyResolver = exports.LogLevel = void 0;
const net = __importStar(require("net"));
const tls = __importStar(require("tls"));
const nodeurl = __importStar(require("url"));
const os = __importStar(require("os"));
const fs = __importStar(require("fs"));
const cp = __importStar(require("child_process"));
const crypto = __importStar(require("crypto"));
const undici = __importStar(require("undici"));
const agent_1 = require("./agent");
var LogLevel;
(function (LogLevel) {
    LogLevel[LogLevel["Trace"] = 0] = "Trace";
    LogLevel[LogLevel["Debug"] = 1] = "Debug";
    LogLevel[LogLevel["Info"] = 2] = "Info";
    LogLevel[LogLevel["Warning"] = 3] = "Warning";
    LogLevel[LogLevel["Error"] = 4] = "Error";
    LogLevel[LogLevel["Critical"] = 5] = "Critical";
    LogLevel[LogLevel["Off"] = 6] = "Off";
})(LogLevel || (exports.LogLevel = LogLevel = {}));
const maxCacheEntries = 5000; // Cache can grow twice that much due to 'oldCache'.
function createProxyResolver(params) {
    const { getProxyURL, log, proxyResolveTelemetry: proxyResolverTelemetry, env } = params;
    let envProxy = proxyFromConfigURL(env.https_proxy || env.HTTPS_PROXY || env.http_proxy || env.HTTP_PROXY); // Not standardized.
    let envNoProxy = noProxyFromEnv(env.no_proxy || env.NO_PROXY); // Not standardized.
    let cacheRolls = 0;
    let oldCache = new Map();
    let cache = new Map();
    let lastNetworkInterfacesCheck = 0;
    let lastNetworkInterfacesSnapshot;
    function checkAndFlushCacheIfNetworkChanged() {
        var _a, _b;
        const intervalMs = (_b = (_a = params.getNetworkInterfaceCheckInterval) === null || _a === void 0 ? void 0 : _a.call(params)) !== null && _b !== void 0 ? _b : -1;
        if (intervalMs < 0) {
            return;
        }
        const now = Date.now();
        if (now - lastNetworkInterfacesCheck >= intervalMs) {
            lastNetworkInterfacesCheck = now;
            const currentSnapshot = JSON.stringify(os.networkInterfaces());
            if (lastNetworkInterfacesSnapshot) {
                if (lastNetworkInterfacesSnapshot !== currentSnapshot) {
                    log.debug('ProxyResolver#getCachedProxy network interfaces changed, flushing cache');
                    cache.clear();
                    oldCache.clear();
                }
                else {
                    log.debug('ProxyResolver#getCachedProxy network interfaces unchanged');
                }
            }
            lastNetworkInterfacesSnapshot = currentSnapshot;
        }
    }
    function getCacheKey(url) {
        // Expecting proxies to usually be the same per scheme://host:port. Assuming that for performance.
        return nodeurl.format(Object.assign(Object.assign({}, url), { pathname: undefined, search: undefined, hash: undefined }));
    }
    function getCachedProxy(key) {
        checkAndFlushCacheIfNetworkChanged();
        let proxy = cache.get(key);
        if (proxy) {
            return proxy;
        }
        proxy = oldCache.get(key);
        if (proxy) {
            oldCache.delete(key);
            cacheProxy(key, proxy);
        }
        return proxy;
    }
    function cacheProxy(key, proxy) {
        cache.set(key, proxy);
        if (cache.size >= maxCacheEntries) {
            oldCache = cache;
            cache = new Map();
            cacheRolls++;
            log.debug('ProxyResolver#cacheProxy cacheRolls', cacheRolls);
        }
    }
    let timeout;
    let count = 0;
    let duration = 0;
    let errorCount = 0;
    let cacheCount = 0;
    let envCount = 0;
    let settingsCount = 0;
    let localhostCount = 0;
    let envNoProxyCount = 0;
    let configNoProxyCount = 0;
    let results = [];
    function logEvent() {
        timeout = undefined;
        proxyResolverTelemetry({ count, duration, errorCount, cacheCount, cacheSize: cache.size, cacheRolls, envCount, settingsCount, localhostCount, envNoProxyCount, configNoProxyCount, results });
        count = duration = errorCount = cacheCount = envCount = settingsCount = localhostCount = envNoProxyCount = configNoProxyCount = 0;
        results = [];
    }
    function resolveProxyWithRequest(flags, req, opts, url, callback) {
        if (!timeout) {
            timeout = setTimeout(logEvent, 10 * 60 * 1000);
        }
        const stackText = ''; // getLogLevel() === LogLevel.Trace ? '\n' + new Error('Error for stack trace').stack : '';
        addCertificatesToOptionsV1(params, flags.addCertificatesV1, opts, () => {
            if (!flags.useProxySettings) {
                callback('DIRECT');
                return;
            }
            useProxySettings(url, req, stackText, callback);
        }, flags.testCertificates);
    }
    function useProxySettings(url, req, stackText, callback) {
        const parsedUrl = nodeurl.parse(url); // Coming from Node's URL, sticking with that.
        const hostname = parsedUrl.hostname;
        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '::ffff:127.0.0.1') {
            localhostCount++;
            callback('DIRECT');
            log.debug('ProxyResolver#resolveProxy localhost', url, 'DIRECT', stackText);
            return;
        }
        const secureEndpoint = parsedUrl.protocol === 'https:';
        const defaultPort = secureEndpoint ? 443 : 80;
        // if there are any config entries present then env variables are ignored
        let noProxyConfig = params.getNoProxyConfig ? params.getNoProxyConfig() : [];
        if (noProxyConfig.length) {
            let configNoProxy = noProxyFromConfig(noProxyConfig); // Not standardized.
            if (typeof hostname === 'string' && configNoProxy(hostname, String(parsedUrl.port || defaultPort))) {
                configNoProxyCount++;
                callback('DIRECT');
                log.debug('ProxyResolver#resolveProxy configNoProxy', url, 'DIRECT', stackText);
                return;
            }
        }
        else {
            if (typeof hostname === 'string' && envNoProxy(hostname, String(parsedUrl.port || defaultPort))) {
                envNoProxyCount++;
                callback('DIRECT');
                log.debug('ProxyResolver#resolveProxy envNoProxy', url, 'DIRECT', stackText);
                return;
            }
        }
        let settingsProxy = proxyFromConfigURL(getProxyURL());
        if (settingsProxy) {
            settingsCount++;
            callback(settingsProxy);
            log.debug('ProxyResolver#resolveProxy settings', url, settingsProxy, stackText);
            return;
        }
        if (envProxy) {
            envCount++;
            callback(envProxy);
            log.debug('ProxyResolver#resolveProxy env', url, envProxy, stackText);
            return;
        }
        if (!params.isUseHostProxyEnabled()) {
            callback('DIRECT');
            log.debug('ProxyResolver#resolveProxy unconfigured', url, 'DIRECT', stackText);
            return;
        }
        const key = getCacheKey(parsedUrl);
        const proxy = getCachedProxy(key);
        if (proxy) {
            cacheCount++;
            if (req) {
                collectResult(results, proxy, secureEndpoint ? 'HTTPS' : 'HTTP', req);
            }
            callback(proxy);
            log.debug('ProxyResolver#resolveProxy cached', url, proxy, stackText);
            return;
        }
        const start = Date.now();
        params.resolveProxy(url) // Use full URL to ensure it is an actually used one.
            .then(proxy => {
            if (proxy) {
                cacheProxy(key, proxy);
                if (req) {
                    collectResult(results, proxy, secureEndpoint ? 'HTTPS' : 'HTTP', req);
                }
            }
            callback(proxy);
            log.debug('ProxyResolver#resolveProxy', url, proxy, stackText);
        }).then(() => {
            count++;
            duration = Date.now() - start + duration;
        }, err => {
            errorCount++;
            const fallback = cache.values().next().value; // fall back to any proxy (https://github.com/microsoft/vscode/issues/122825)
            callback(fallback);
            log.error('ProxyResolver#resolveProxy', fallback, toErrorMessage(err), stackText);
        });
    }
    return {
        resolveProxyWithRequest,
        resolveProxyURL: (url) => new Promise((resolve, reject) => {
            useProxySettings(url, undefined, '', result => {
                try {
                    resolve((0, agent_1.getProxyURLFromResolverResult)(result).url);
                }
                catch (err) {
                    reject(err);
                }
            });
        }),
    };
}
exports.createProxyResolver = createProxyResolver;
function collectResult(results, resolveProxy, connection, req) {
    const proxy = resolveProxy ? String(resolveProxy).trim().split(/\s+/, 1)[0] : 'EMPTY';
    req.on('response', res => {
        const code = `HTTP_${res.statusCode}`;
        const result = findOrCreateResult(results, proxy, connection, code);
        result.count++;
    });
    req.on('error', err => {
        const code = err && typeof err.code === 'string' && err.code || 'UNKNOWN_ERROR';
        const result = findOrCreateResult(results, proxy, connection, code);
        result.count++;
    });
}
function findOrCreateResult(results, proxy, connection, code) {
    for (const result of results) {
        if (result.proxy === proxy && result.connection === connection && result.code === code) {
            return result;
        }
    }
    const result = { proxy, connection, code, count: 0 };
    results.push(result);
    return result;
}
function proxyFromConfigURL(configURL) {
    if (!configURL) {
        return undefined;
    }
    const url = (configURL || '').trim();
    const i = url.indexOf('://');
    if (i === -1) {
        return undefined;
    }
    const scheme = url.substr(0, i).toLowerCase();
    const proxy = url.substr(i + 3);
    if (scheme === 'http') {
        return 'PROXY ' + proxy;
    }
    else if (scheme === 'https') {
        return 'HTTPS ' + proxy;
    }
    else if (scheme === 'socks' || scheme === 'socks5' || scheme === 'socks5h') {
        return 'SOCKS ' + proxy;
    }
    else if (scheme === 'socks4' || scheme === 'socks4a') {
        return 'SOCKS4 ' + proxy;
    }
    return undefined;
}
function shouldBypassProxy(value) {
    if (value.includes("*")) {
        return () => true;
    }
    const filters = value
        .map(s => s.trim().split(':', 2))
        .map(([name, port]) => ({ name, port }))
        .filter(filter => !!filter.name)
        .map(({ name, port }) => {
        const domain = name[0] === '.' ? name : `.${name}`;
        return { domain, port };
    });
    if (!filters.length) {
        return () => false;
    }
    return (hostname, port) => filters.some(({ domain, port: filterPort }) => {
        return `.${hostname.toLowerCase()}`.endsWith(domain) && (!filterPort || port === filterPort);
    });
}
function noProxyFromEnv(envValue) {
    const value = (envValue || '')
        .trim()
        .toLowerCase()
        .split(',');
    return shouldBypassProxy(value);
}
function noProxyFromConfig(noProxy) {
    const value = noProxy
        .map((item) => item.trim().toLowerCase());
    return shouldBypassProxy(value);
}
function createHttpPatch(params, originals, resolveProxy) {
    return {
        get: patch(originals.get),
        request: patch(originals.request)
    };
    function patch(original) {
        function patched(url, options, callback) {
            if (typeof url !== 'string' && !(url && url.searchParams)) {
                callback = options;
                options = url;
                url = null;
            }
            if (typeof options === 'function') {
                callback = options;
                options = null;
            }
            options = options || {};
            if (options.socketPath) {
                return original.apply(null, arguments);
            }
            const originalAgent = options.agent;
            if (originalAgent === true) {
                throw new Error('Unexpected agent option: true');
            }
            const isHttps = originals.globalAgent.protocol === 'https:';
            const optionsPatched = originalAgent instanceof agent_1.PacProxyAgent;
            const config = params.getProxySupport();
            const useProxySettings = !optionsPatched && (config === 'override' || config === 'fallback' || (config === 'on' && originalAgent === undefined));
            // If Agent.options.ca is set to undefined, it overwrites RequestOptions.ca.
            const originalOptionsCa = isHttps ? options.ca : undefined;
            const originalAgentCa = isHttps && originalAgent instanceof originals.Agent && originalAgent.options && 'ca' in originalAgent.options && originalAgent.options.ca;
            const originalCa = originalAgentCa !== false ? originalAgentCa : originalOptionsCa;
            const addCertificatesV1 = !optionsPatched && params.addCertificatesV1() && isHttps && !originalCa;
            if (useProxySettings || addCertificatesV1) {
                if (url) {
                    const parsed = typeof url === 'string' ? new nodeurl.URL(url) : url;
                    const urlOptions = {
                        protocol: parsed.protocol,
                        hostname: parsed.hostname.lastIndexOf('[', 0) === 0 ? parsed.hostname.slice(1, -1) : parsed.hostname,
                        port: parsed.port,
                        path: `${parsed.pathname}${parsed.search}`
                    };
                    if (parsed.username || parsed.password) {
                        options.auth = `${parsed.username}:${parsed.password}`;
                    }
                    options = Object.assign(Object.assign({}, urlOptions), options);
                }
                else {
                    options = Object.assign({}, options);
                }
                const resolveP = (req, opts, url) => new Promise(resolve => resolveProxy({ useProxySettings, addCertificatesV1, testCertificates: options.testCertificates }, req, opts, url, resolve));
                const host = options.hostname || options.host;
                const isLocalhost = !host || host === 'localhost' || host === '127.0.0.1'; // Avoiding https://github.com/microsoft/vscode/issues/120354
                const agent = (0, agent_1.createPacProxyAgent)(resolveP, {
                    originalAgent: (!useProxySettings || isLocalhost || config === 'fallback') ? originalAgent : undefined,
                    lookupProxyAuthorization: params.lookupProxyAuthorization,
                    // keepAlive: ((originalAgent || originals.globalAgent) as { keepAlive?: boolean }).keepAlive, // Skipping due to https://github.com/microsoft/vscode/issues/228872.
                    _vscodeTestReplaceCaCerts: options._vscodeTestReplaceCaCerts,
                }, opts => new Promise(resolve => addCertificatesToOptionsV1(params, params.addCertificatesV1(), opts, resolve, options.testCertificates)));
                agent.protocol = isHttps ? 'https:' : 'http:';
                options.agent = agent;
                if (isHttps) {
                    options.ca = originalCa;
                }
                return original(options, callback);
            }
            return original.apply(null, arguments);
        }
        return patched;
    }
}
exports.createHttpPatch = createHttpPatch;
function createNetPatch(params, originals) {
    return {
        connect: patchNetConnect(params, originals.connect),
    };
}
exports.createNetPatch = createNetPatch;
function patchNetConnect(params, original) {
    function connect(...args) {
        if (params.getLogLevel() === LogLevel.Trace) {
            params.log.trace('ProxyResolver#net.connect', toLogString(args));
        }
        if (!params.addCertificatesV2()) {
            return original.apply(null, arguments);
        }
        const socket = new net.Socket();
        socket.connecting = true;
        getOrLoadAdditionalCertificates(params)
            .then(() => {
            const options = args.find(arg => arg && typeof arg === 'object');
            if (options === null || options === void 0 ? void 0 : options.timeout) {
                socket.setTimeout(options.timeout);
            }
            socket.connect.apply(socket, arguments);
        })
            .catch(err => {
            params.log.error('ProxyResolver#net.connect', toErrorMessage(err));
        });
        return socket;
    }
    return connect;
}
function createTlsPatch(params, originals) {
    return {
        connect: patchTlsConnect(params, originals.connect),
        createSecureContext: patchCreateSecureContext(originals.createSecureContext),
    };
}
exports.createTlsPatch = createTlsPatch;
function patchTlsConnect(params, original) {
    function connect(...args) {
        var _a;
        if (params.getLogLevel() === LogLevel.Trace) {
            params.log.trace('ProxyResolver#tls.connect', toLogString(args));
        }
        let options = args.find(arg => arg && typeof arg === 'object');
        if (!params.addCertificatesV2() || (options === null || options === void 0 ? void 0 : options.ca)) {
            return original.apply(null, arguments);
        }
        const testCerts = options === null || options === void 0 ? void 0 : options.testCertificates;
        let secureConnectListener = args.find(arg => typeof arg === 'function');
        if (!options) {
            options = {};
            const listenerIndex = args.findIndex(arg => typeof arg === 'function');
            if (listenerIndex !== -1) {
                args[listenerIndex - 1] = options;
            }
            else {
                args[2] = options;
            }
        }
        else {
            options = Object.assign({}, options);
        }
        const port = typeof args[0] === 'number' ? args[0]
            : typeof args[0] === 'string' && !isNaN(Number(args[0])) ? Number(args[0]) // E.g., http2 module passes port as string.
                : options.port;
        const host = typeof args[1] === 'string' ? args[1] : options.host;
        let tlsSocket;
        if (options.socket) {
            if (!options.secureContext) {
                options.secureContext = tls.createSecureContext(options);
            }
            const certificates = (_a = _certs.get(!!params.loadSystemCertificatesFromNode())) === null || _a === void 0 ? void 0 : _a.result;
            if (!certificates) {
                params.log.trace('ProxyResolver#tls.connect waiting for existing socket connect');
                options.socket.once('connect', () => {
                    var _a;
                    params.log.trace('ProxyResolver#tls.connect got existing socket connect - adding certs');
                    for (const cert of ((_a = _certs.get(!!params.loadSystemCertificatesFromNode())) === null || _a === void 0 ? void 0 : _a.result) || []) {
                        options.secureContext.context.addCACert(cert);
                    }
                    if (testCerts) {
                        for (const cert of testCerts) {
                            options.secureContext.context.addCACert(cert);
                        }
                    }
                });
            }
            else {
                params.log.trace('ProxyResolver#tls.connect existing socket already connected - adding certs');
                for (const cert of certificates) {
                    options.secureContext.context.addCACert(cert);
                }
                if (testCerts) {
                    for (const cert of testCerts) {
                        options.secureContext.context.addCACert(cert);
                    }
                }
            }
        }
        else {
            if (!options.secureContext) {
                options.secureContext = tls.createSecureContext(options);
            }
            params.log.trace('ProxyResolver#tls.connect creating unconnected socket');
            const socket = options.socket = new net.Socket();
            socket.connecting = true;
            getOrLoadAdditionalCertificates(params)
                .then(caCertificates => {
                params.log.trace('ProxyResolver#tls.connect adding certs before connecting socket');
                for (const cert of caCertificates) {
                    options.secureContext.context.addCACert(cert);
                }
                if (testCerts) {
                    for (const cert of testCerts) {
                        options.secureContext.context.addCACert(cert);
                    }
                }
                if (options === null || options === void 0 ? void 0 : options.timeout) {
                    socket.setTimeout(options.timeout);
                    socket.once('timeout', () => {
                        tlsSocket.emit('timeout');
                    });
                }
                socket.connect(Object.assign({ port: port, host }, options));
            })
                .catch(err => {
                params.log.error('ProxyResolver#tls.connect', toErrorMessage(err));
            });
        }
        if (typeof args[1] === 'string') {
            tlsSocket = original(port, host, options, secureConnectListener);
        }
        else if (typeof args[0] === 'number' || typeof args[0] === 'string' && !isNaN(Number(args[0]))) {
            tlsSocket = original(port, options, secureConnectListener);
        }
        else {
            tlsSocket = original(options, secureConnectListener);
        }
        return tlsSocket;
    }
    return connect;
}
function patchCreateSecureContext(original) {
    return function (details) {
        const context = original.apply(null, arguments);
        const certs = details === null || details === void 0 ? void 0 : details._vscodeAdditionalCaCerts;
        if (certs) {
            for (const cert of certs) {
                context.context.addCACert(cert);
            }
        }
        return context;
    };
}
function createFetchPatch(params, originalFetch, resolveProxyURL, options) {
    const interceptors = options === null || options === void 0 ? void 0 : options.interceptors;
    const hasInterceptors = !!interceptors && interceptors.length > 0;
    // Caches the composed dispatcher per base agent so all requests share the
    // same composed dispatcher.
    const composedAgentCache = hasInterceptors ? new WeakMap() : undefined;
    function withInterceptors(agent) {
        if (!agent || !composedAgentCache) {
            return agent;
        }
        let composed = composedAgentCache.get(agent);
        if (!composed) {
            composed = agent.compose(...interceptors);
            composedAgentCache.set(agent, composed);
        }
        return composed;
    }
    return function patchedFetch(input, init) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!params.isAdditionalFetchSupportEnabled()) {
                return originalFetch(input, init);
            }
            const agentOptions = getAgentOptions(init);
            if (agentOptions.socketPath) {
                return originalFetch(input, init);
            }
            const proxySupport = params.getProxySupport();
            const doResolveProxy = proxySupport === 'override' || proxySupport === 'fallback' || (proxySupport === 'on' && (init === null || init === void 0 ? void 0 : init.dispatcher) === undefined);
            const addCerts = params.addCertificatesV1() || params.addCertificatesV2(); // There is no v2 for `fetch`, checking both settings.
            if (!doResolveProxy && !addCerts) {
                return originalFetch(input, init);
            }
            const urlString = typeof input === 'string' ? input : 'cache' in input ? input.url : input.toString();
            const proxyURL = doResolveProxy ? yield resolveProxyURL(urlString) : undefined;
            if (!proxyURL && !addCerts) {
                return originalFetch(input, init);
            }
            const systemCA = addCerts ? [...tls.rootCertificates, ...yield getOrLoadAdditionalCertificates(params)] : undefined;
            const { allowH2 } = agentOptions;
            const requestCA = agentOptions.requestCA || systemCA;
            const proxyCA = agentOptions.proxyCA || systemCA;
            if (!proxyURL) {
                const modifiedInit = Object.assign(Object.assign({}, init), { dispatcher: withInterceptors(getAgent(agentOptions.dispatcher, allowH2, requestCA, addCerts)) });
                return originalFetch(input, modifiedInit);
            }
            const modifiedInit = Object.assign(Object.assign({}, init), { dispatcher: withInterceptors(getProxyAgent(params, agentOptions.dispatcher, proxyURL, allowH2, requestCA, proxyCA, addCerts)) });
            return originalFetch(input, modifiedInit);
        });
    };
}
exports.createFetchPatch = createFetchPatch;
let previousAddCertsAgent = undefined;
let defaultAgent = undefined;
let agentCache = new WeakMap();
function getAgent(originalDispatcher, allowH2, requestCA, currentAddCerts) {
    if (previousAddCertsAgent !== currentAddCerts) {
        previousAddCertsAgent = currentAddCerts;
        defaultAgent = undefined;
        agentCache = new WeakMap();
    }
    if (!originalDispatcher) {
        if (!defaultAgent) {
            defaultAgent = createAgent(allowH2, requestCA);
        }
        return defaultAgent;
    }
    if (!agentCache.has(originalDispatcher)) {
        agentCache.set(originalDispatcher, createAgent(allowH2, requestCA));
    }
    return agentCache.get(originalDispatcher);
}
function createAgent(allowH2, requestCA) {
    return new undici.Agent({
        allowH2,
        connect: { ca: requestCA },
    });
}
let previousAddCertsProxyAgent = undefined;
let previousLookupProxyAuthorization = undefined;
let defaultProxyAgents = new Map();
let proxyAgentCache = new WeakMap();
function getProxyAgent(params, originalDispatcher, proxyURL, allowH2, requestCA, proxyCA, currentAddCerts) {
    const shouldClearCache = previousAddCertsProxyAgent !== currentAddCerts || previousLookupProxyAuthorization !== params.lookupProxyAuthorization;
    if (shouldClearCache) {
        previousAddCertsProxyAgent = currentAddCerts;
        previousLookupProxyAuthorization = params.lookupProxyAuthorization;
        defaultProxyAgents = new Map();
        proxyAgentCache = new WeakMap();
    }
    if (!originalDispatcher) {
        if (!defaultProxyAgents.has(proxyURL)) {
            defaultProxyAgents.set(proxyURL, createProxyAgent(params, proxyURL, allowH2, requestCA, proxyCA));
        }
        return defaultProxyAgents.get(proxyURL);
    }
    let dispatcherCache = proxyAgentCache.get(originalDispatcher);
    if (!dispatcherCache) {
        dispatcherCache = new Map();
        proxyAgentCache.set(originalDispatcher, dispatcherCache);
    }
    if (!dispatcherCache.has(proxyURL)) {
        dispatcherCache.set(proxyURL, createProxyAgent(params, proxyURL, allowH2, requestCA, proxyCA));
    }
    return dispatcherCache.get(proxyURL);
}
function createProxyAgent(params, proxyURL, allowH2, requestCA, proxyCA) {
    return new undici.ProxyAgent({
        uri: proxyURL,
        allowH2,
        requestTls: requestCA ? { allowH2, ca: requestCA } : { allowH2 },
        proxyTls: proxyCA ? { allowH2, ca: proxyCA } : { allowH2 },
        clientFactory: (origin, opts) => new undici.Pool(origin, opts).compose((dispatch) => {
            class ProxyAuthHandler extends undici.DecoratorHandler {
                constructor(dispatch, options, handler, state) {
                    super(handler);
                    this.dispatch = dispatch;
                    this.options = options;
                    this.handler = handler;
                    this.state = state;
                }
                forwardResponseError(controller, err) {
                    var _a, _b;
                    if (this.connectResponseHeaders) {
                        err.connectResponseHeaders = this.connectResponseHeaders;
                    }
                    if (this.connectResponseStatusCode !== undefined) {
                        err.connectResponseStatusCode = this.connectResponseStatusCode;
                    }
                    (_b = (_a = this.handler).onResponseError) === null || _b === void 0 ? void 0 : _b.call(_a, controller, err);
                }
                onResponseError(controller, err) {
                    if (!(err instanceof ProxyAuthError)) {
                        return this.forwardResponseError(controller, err);
                    }
                    (() => __awaiter(this, void 0, void 0, function* () {
                        var _a;
                        try {
                            const proxyAuthorization = yield ((_a = params.lookupProxyAuthorization) === null || _a === void 0 ? void 0 : _a.call(params, proxyURL, err.proxyAuthenticate, this.state));
                            if (proxyAuthorization) {
                                setProxyAuthorizationHeader(this.options, proxyAuthorization);
                                this.dispatch(this.options, this);
                            }
                            else {
                                this.forwardResponseError(controller, new undici.errors.RequestAbortedError(`Proxy response (407) ?.== 200 when HTTP Tunneling`)); // Mimick undici's behavior
                            }
                        }
                        catch (err) {
                            this.forwardResponseError(controller, err);
                        }
                    }))();
                }
                onRequestUpgrade(controller, statusCode, headers, socket) {
                    var _a, _b;
                    this.connectResponseHeaders = headers;
                    this.connectResponseStatusCode = statusCode;
                    if (statusCode === 407 && headers) {
                        let proxyAuthenticate;
                        for (const header in headers) {
                            if (header.toLowerCase() === 'proxy-authenticate') {
                                proxyAuthenticate = headers[header];
                                break;
                            }
                        }
                        if (proxyAuthenticate) {
                            controller.abort(new ProxyAuthError(proxyAuthenticate));
                            return;
                        }
                    }
                    (_b = (_a = this.handler).onRequestUpgrade) === null || _b === void 0 ? void 0 : _b.call(_a, controller, statusCode, headers, socket);
                }
            }
            return function proxyAuthDispatch(options, handler) {
                const state = {};
                (() => __awaiter(this, void 0, void 0, function* () {
                    var _a;
                    try {
                        const proxyAuthorization = yield ((_a = params.lookupProxyAuthorization) === null || _a === void 0 ? void 0 : _a.call(params, proxyURL, undefined, state));
                        if (proxyAuthorization) {
                            setProxyAuthorizationHeader(options, proxyAuthorization);
                        }
                    }
                    catch (err) {
                        // 407 handler will retry with auth.
                        params.log.error('ProxyResolver#proxyAuthDispatch lookupProxyAuthorization failed', toErrorMessage(err));
                    }
                    dispatch(options, new ProxyAuthHandler(dispatch, options, handler, state));
                }))();
            };
        }),
    });
}
function createWebSocketPatch(params, originalWebSocket, resolveProxyURL) {
    const PatchedWebSocket = function WebSocket(url, protocols) {
        if (!params.isWebSocketPatchEnabled()) {
            return new originalWebSocket(url, protocols);
        }
        const proxySupport = params.getProxySupport();
        const addCerts = params.addCertificatesV1() || params.addCertificatesV2();
        let init;
        if (protocols === undefined || protocols === null) {
            init = {};
        }
        else if (typeof protocols === 'string' || Array.isArray(protocols)) {
            init = { protocols };
        }
        else {
            init = Object.assign({}, protocols);
        }
        const hasCallerDispatcher = init.dispatcher !== undefined;
        const doResolveProxy = proxySupport === 'override' || proxySupport === 'fallback' || (proxySupport === 'on' && !hasCallerDispatcher);
        if (!doResolveProxy && !addCerts) {
            return new originalWebSocket(url, protocols);
        }
        const proxyDispatcher = new ProxyDispatcher(params, resolveProxyURL, doResolveProxy, addCerts, init.dispatcher);
        init.dispatcher = proxyDispatcher;
        const ws = new originalWebSocket(url, init);
        Object.defineProperty(ws, 'responseHeaders', {
            get() { return proxyDispatcher.responseHeaders; },
            enumerable: true,
            configurable: true,
        });
        Object.defineProperty(ws, 'responseStatusCode', {
            get() { return proxyDispatcher.responseStatusCode; },
            enumerable: true,
            configurable: true,
        });
        Object.defineProperty(ws, 'responseStatusText', {
            get() { return proxyDispatcher.responseStatusText; },
            enumerable: true,
            configurable: true,
        });
        Object.defineProperty(ws, 'networkError', {
            get() { return proxyDispatcher.networkError; },
            enumerable: true,
            configurable: true,
        });
        return ws;
    };
    PatchedWebSocket.prototype = originalWebSocket.prototype;
    Object.defineProperties(PatchedWebSocket, {
        CONNECTING: { value: originalWebSocket.CONNECTING, enumerable: true },
        OPEN: { value: originalWebSocket.OPEN, enumerable: true },
        CLOSING: { value: originalWebSocket.CLOSING, enumerable: true },
        CLOSED: { value: originalWebSocket.CLOSED, enumerable: true },
    });
    return PatchedWebSocket;
}
exports.createWebSocketPatch = createWebSocketPatch;
class ProxyDispatcher extends undici.Dispatcher {
    constructor(params, resolveProxyURL, doResolveProxy, addCerts, originalDispatcher) {
        super();
        this.params = params;
        this.resolveProxyURL = resolveProxyURL;
        this.doResolveProxy = doResolveProxy;
        this.addCerts = addCerts;
        this.originalDispatcher = originalDispatcher;
    }
    dispatch(opts, handler) {
        var _a;
        const self = this;
        function captureError(err) {
            const connectHeaders = err.connectResponseHeaders;
            if (connectHeaders) {
                self.responseHeaders = convertHeaders(connectHeaders);
            }
            if (err.connectResponseStatusCode !== undefined) {
                self.responseStatusCode = err.connectResponseStatusCode;
            }
            if (!self.networkError) {
                self.networkError = err;
            }
        }
        const wrappedHandler = Object.assign(Object.assign({}, handler), { 
            // Current API.
            onResponseStart(controller, statusCode, headers, statusMessage) {
                var _a;
                self.responseStatusCode = statusCode;
                self.responseStatusText = statusMessage;
                self.responseHeaders = convertHeaders(headers);
                return (_a = handler.onResponseStart) === null || _a === void 0 ? void 0 : _a.call(handler, controller, statusCode, headers, statusMessage);
            },
            onResponseError(controller, err) {
                var _a;
                captureError(err);
                return (_a = handler.onResponseError) === null || _a === void 0 ? void 0 : _a.call(handler, controller, err);
            },
            onRequestUpgrade(controller, statusCode, headers, socket) {
                var _a;
                self.responseStatusCode = statusCode;
                self.responseHeaders = convertHeaders(headers);
                return (_a = handler.onRequestUpgrade) === null || _a === void 0 ? void 0 : _a.call(handler, controller, statusCode, headers, socket);
            },
            // Deprecated API still used by undici's internal core.
            onHeaders(statusCode, rawHeaders, resume, statusText) {
                var _a, _b, _c;
                self.responseStatusCode = statusCode;
                self.responseStatusText = statusText;
                self.responseHeaders = parseRawHeaders(rawHeaders);
                return (_c = (_b = (_a = handler).onHeaders) === null || _b === void 0 ? void 0 : _b.call(_a, statusCode, rawHeaders, resume, statusText)) !== null && _c !== void 0 ? _c : true;
            },
            onError(err) {
                var _a, _b;
                captureError(err);
                return (_b = (_a = handler).onError) === null || _b === void 0 ? void 0 : _b.call(_a, err);
            },
            onUpgrade(statusCode, rawHeaders, socket) {
                var _a, _b;
                self.responseStatusCode = statusCode;
                if (rawHeaders) {
                    self.responseHeaders = parseRawHeaders(rawHeaders);
                }
                return (_b = (_a = handler).onUpgrade) === null || _b === void 0 ? void 0 : _b.call(_a, statusCode, rawHeaders, socket);
            } });
        const url = (_a = opts.origin) === null || _a === void 0 ? void 0 : _a.toString();
        (() => __awaiter(this, void 0, void 0, function* () {
            var _b;
            try {
                // Map ws:/wss: to http:/https: for proxy resolution
                let resolveURL = url;
                if (resolveURL) {
                    resolveURL = resolveURL.replace(/^ws(s?):/, 'http$1:');
                }
                const proxyURL = this.doResolveProxy && resolveURL ? yield this.resolveProxyURL(resolveURL) : undefined;
                const systemCA = this.addCerts ? [...tls.rootCertificates, ...yield getOrLoadAdditionalCertificates(this.params)] : undefined;
                const callerOptions = getAgentOptions({ dispatcher: this.originalDispatcher });
                const requestCA = callerOptions.requestCA || systemCA;
                const proxyCA = callerOptions.proxyCA || systemCA;
                let dispatcher;
                if (proxyURL) {
                    dispatcher = getProxyAgent(this.params, this.originalDispatcher, proxyURL, callerOptions.allowH2, requestCA, proxyCA, this.addCerts);
                }
                else if (this.addCerts) {
                    dispatcher = getAgent(this.originalDispatcher, callerOptions.allowH2, requestCA, this.addCerts);
                }
                else if (this.originalDispatcher) {
                    dispatcher = this.originalDispatcher;
                }
                else {
                    dispatcher = undici.getGlobalDispatcher();
                }
                dispatcher.dispatch(opts, wrappedHandler);
            }
            catch (err) {
                (_b = handler.onResponseError) === null || _b === void 0 ? void 0 : _b.call(handler, null, err);
            }
        }))();
        return true;
    }
    close() {
        return Promise.resolve();
    }
    destroy() {
        return Promise.resolve();
    }
}
function parseRawHeaders(rawHeaders) {
    const headers = {};
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
        const key = rawHeaders[i].toString().toLowerCase();
        const value = rawHeaders[i + 1].toString();
        const existing = headers[key];
        if (existing === undefined) {
            headers[key] = value;
        }
        else if (Array.isArray(existing)) {
            existing.push(value);
        }
        else {
            headers[key] = [existing, value];
        }
    }
    return headers;
}
function convertHeaders(headers) {
    const result = {};
    for (const key in headers) {
        result[key.toLowerCase()] = headers[key];
    }
    return result;
}
/** @internal Exported for testing */
function setProxyAuthorizationHeader(options, proxyAuthorization) {
    const headers = options.headers;
    if (!headers) {
        options.headers = ['Proxy-Authorization', proxyAuthorization];
    }
    else if (Array.isArray(headers) && (headers.length === 0 || Array.isArray(headers[0]))) {
        // Tuple array format: [['Header1', 'value1'], ['Header2', 'value2'], ...]
        const tuplesArray = headers;
        const i = tuplesArray.findIndex(([key]) => key.toLowerCase() === 'proxy-authorization');
        if (i === -1) {
            tuplesArray.push(['Proxy-Authorization', proxyAuthorization]);
        }
        else {
            tuplesArray[i][1] = proxyAuthorization;
        }
    }
    else if (Array.isArray(headers)) {
        // Flat array format: ['Header1', 'value1', 'Header2', 'value2', ...]
        const i = headers.findIndex((value, index) => index % 2 === 0 && typeof value === 'string' && value.toLowerCase() === 'proxy-authorization');
        if (i === -1) {
            headers.push('Proxy-Authorization', proxyAuthorization);
        }
        else {
            headers[i + 1] = proxyAuthorization;
        }
    }
    else if (Symbol.iterator in headers) {
        // Iterable of tuples format (e.g., Map): [['Header1', 'value1'], ['Header2', 'value2'], ...]
        const headersArray = [...headers];
        const i = headersArray.findIndex(([key]) => key.toLowerCase() === 'proxy-authorization');
        if (i === -1) {
            headersArray.push(['Proxy-Authorization', proxyAuthorization]);
        }
        else {
            headersArray[i][1] = proxyAuthorization;
        }
        options.headers = headersArray;
    }
    else {
        // Record format: { 'Header1': 'value1', 'Header2': 'value2', ... }
        headers['Proxy-Authorization'] = proxyAuthorization;
    }
}
exports.setProxyAuthorizationHeader = setProxyAuthorizationHeader;
class ProxyAuthError extends Error {
    constructor(proxyAuthenticate) {
        super('Proxy authentication required');
        this.proxyAuthenticate = proxyAuthenticate;
    }
}
const agentOptions = Symbol('agentOptions');
const proxyAgentOptions = Symbol('proxyAgentOptions');
function patchUndici(originalUndici) {
    const originalAgent = originalUndici.Agent;
    const patchedAgent = function PatchedAgent(opts) {
        const agent = new originalAgent(opts);
        agent[agentOptions] = Object.assign(Object.assign({}, opts), ((opts === null || opts === void 0 ? void 0 : opts.connect) && typeof (opts === null || opts === void 0 ? void 0 : opts.connect) === 'object' ? { connect: Object.assign({}, opts.connect) } : undefined));
        return agent;
    };
    patchedAgent.prototype = originalAgent.prototype;
    originalUndici.Agent = patchedAgent;
    const originalProxyAgent = originalUndici.ProxyAgent;
    const patchedProxyAgent = function PatchedProxyAgent(opts) {
        const proxyAgent = new originalProxyAgent(opts);
        proxyAgent[proxyAgentOptions] = typeof opts === 'string' ? opts : Object.assign(Object.assign({}, opts), ((opts === null || opts === void 0 ? void 0 : opts.connect) && typeof (opts === null || opts === void 0 ? void 0 : opts.connect) === 'object' ? { connect: Object.assign({}, opts.connect) } : undefined));
        return proxyAgent;
    };
    patchedProxyAgent.prototype = originalProxyAgent.prototype;
    originalUndici.ProxyAgent = patchedProxyAgent;
}
exports.patchUndici = patchUndici;
function getAgentOptions(requestInit) {
    let allowH2;
    let requestCA;
    let proxyCA;
    let socketPath;
    const dispatcher = requestInit === null || requestInit === void 0 ? void 0 : requestInit.dispatcher;
    let originalAgentOptions = dispatcher && dispatcher[agentOptions];
    if (dispatcher && !originalAgentOptions) {
        // Handles bundled extension code where undici does not get patched.
        const optionsSymbol = Object.getOwnPropertySymbols(dispatcher).find(s => s.description === 'options');
        if (optionsSymbol) {
            originalAgentOptions = dispatcher[optionsSymbol];
        }
    }
    if (originalAgentOptions && typeof originalAgentOptions === 'object') {
        allowH2 = originalAgentOptions.allowH2;
        if (originalAgentOptions.connect && typeof originalAgentOptions.connect === 'object') {
            requestCA = 'ca' in originalAgentOptions.connect && originalAgentOptions.connect.ca || undefined;
            socketPath = originalAgentOptions.connect.socketPath || undefined;
        }
    }
    let originalProxyAgentOptions = dispatcher && dispatcher[proxyAgentOptions];
    if (dispatcher && !originalProxyAgentOptions) {
        // Handles bundled extension code where undici does not get patched.
        const proxyAgentSymbol = Object.getOwnPropertySymbols(dispatcher).find(s => s.description === 'proxy agent');
        if (proxyAgentSymbol) {
            const proxyAgent = dispatcher[proxyAgentSymbol];
            if (proxyAgent && typeof proxyAgent === 'object') {
                const optionsSymbol = Object.getOwnPropertySymbols(proxyAgent).find(s => s.description === 'options');
                if (optionsSymbol) {
                    originalProxyAgentOptions = proxyAgent[optionsSymbol];
                }
            }
        }
    }
    if (originalProxyAgentOptions && typeof originalProxyAgentOptions === 'object') {
        allowH2 = originalProxyAgentOptions.allowH2;
        requestCA = originalProxyAgentOptions.requestTls && 'ca' in originalProxyAgentOptions.requestTls && originalProxyAgentOptions.requestTls.ca || undefined;
        proxyCA = originalProxyAgentOptions.proxyTls && 'ca' in originalProxyAgentOptions.proxyTls && originalProxyAgentOptions.proxyTls.ca || undefined;
    }
    return { dispatcher, allowH2, requestCA, proxyCA, socketPath };
}
function addCertificatesToOptionsV1(params, addCertificatesV1, opts, callback, testCertificates) {
    if (addCertificatesV1) {
        getOrLoadAdditionalCertificates(params)
            .then(caCertificates => {
            const allCerts = (testCertificates === null || testCertificates === void 0 ? void 0 : testCertificates.length) ? [...caCertificates, ...testCertificates] : caCertificates;
            if (opts._vscodeTestReplaceCaCerts) {
                opts.ca = allCerts;
            }
            else {
                opts._vscodeAdditionalCaCerts = allCerts;
            }
            callback();
        })
            .catch(err => {
            params.log.error('ProxyResolver#addCertificatesV1', toErrorMessage(err));
        });
    }
    else {
        callback();
    }
}
const _certs = new Map();
function getOrLoadAdditionalCertificates(params) {
    return __awaiter(this, void 0, void 0, function* () {
        const loadFromNode = !!params.loadSystemCertificatesFromNode();
        if (!_certs.has(loadFromNode)) {
            const cert = {
                promise: (() => __awaiter(this, void 0, void 0, function* () {
                    const result = yield params.loadAdditionalCertificates();
                    return cert.result = result; // need to await before accessing cert.
                }))(),
                result: undefined
            };
            _certs.set(loadFromNode, cert);
        }
        return _certs.get(loadFromNode).promise;
    });
}
exports.getOrLoadAdditionalCertificates = getOrLoadAdditionalCertificates;
function filterExpiredCertificates(params, certs) {
    const now = Date.now();
    const filtered = certs
        .filter(cert => {
        try {
            const parsedCert = new crypto.X509Certificate(cert);
            const parsedDate = Date.parse(parsedCert.validTo);
            return isNaN(parsedDate) || parsedDate > now;
        }
        catch (err) {
            params.log.debug('ProxyResolver#filterExpiredCertificates parse error', toErrorMessage(err));
            return false;
        }
    });
    params.log.debug('ProxyResolver#filterExpiredCertificates count filtered', filtered.length);
    return filtered;
}
let _systemCertificatesPromise;
function loadSystemCertificates(params) {
    var _a;
    return __awaiter(this, void 0, void 0, function* () {
        if (!!((_a = params.loadSystemCertificatesFromNode) === null || _a === void 0 ? void 0 : _a.call(params))) { // Checking if function exists for backward compatibility.
            const start = Date.now();
            const systemCerts = tls.getCACertificates('system');
            params.log.debug(`ProxyResolver#loadSystemCertificates from Node.js count (${Date.now() - start}ms)`, systemCerts.length);
            return filterExpiredCertificates(params, systemCerts);
        }
        if (!_systemCertificatesPromise) {
            _systemCertificatesPromise = (() => __awaiter(this, void 0, void 0, function* () {
                try {
                    const start = Date.now();
                    const certs = yield readSystemCertificates();
                    params.log.debug(`ProxyResolver#loadSystemCertificates count (${Date.now() - start}ms)`, certs.length);
                    return filterExpiredCertificates(params, certs);
                }
                catch (err) {
                    params.log.error('ProxyResolver#loadSystemCertificates error', toErrorMessage(err));
                    return [];
                }
            }))();
        }
        return _systemCertificatesPromise;
    });
}
exports.loadSystemCertificates = loadSystemCertificates;
function resetCaches() {
    _certs.clear();
    _systemCertificatesPromise = undefined;
}
exports.resetCaches = resetCaches;
function readSystemCertificates() {
    return __awaiter(this, void 0, void 0, function* () {
        if (process.platform === 'win32') {
            return readWindowsCaCertificates();
        }
        if (process.platform === 'darwin') {
            return readMacCaCertificates();
        }
        if (process.platform === 'linux') {
            return readLinuxCaCertificates();
        }
        return [];
    });
}
function readWindowsCaCertificates() {
    return __awaiter(this, void 0, void 0, function* () {
        // @ts-ignore Windows only
        const winCA = yield Promise.resolve().then(() => __importStar(require('@vscode/windows-ca-certs')));
        let ders = [];
        const store = new winCA.Crypt32();
        try {
            let der;
            while (der = store.next()) {
                ders.push(der);
            }
        }
        finally {
            store.done();
        }
        const certs = new Set(ders.map(derToPem));
        return Array.from(certs);
    });
}
function readMacCaCertificates() {
    return __awaiter(this, void 0, void 0, function* () {
        const stdout = yield new Promise((resolve, reject) => {
            const child = cp.spawn('/usr/bin/security', ['find-certificate', '-a', '-p']);
            const stdout = [];
            child.stdout.setEncoding('utf8');
            child.stdout.on('data', str => stdout.push(str));
            child.on('error', reject);
            child.on('exit', code => code ? reject(code) : resolve(stdout.join('')));
        });
        const certs = new Set(stdout.split(/(?=-----BEGIN CERTIFICATE-----)/g)
            .filter(pem => !!pem.length));
        return Array.from(certs);
    });
}
const linuxCaCertificatePaths = [
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/ssl/certs/ca-bundle.crt',
    '/etc/ssl/ca-bundle.pem',
    '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', // Fedora 43+
];
function readLinuxCaCertificates() {
    return __awaiter(this, void 0, void 0, function* () {
        for (const certPath of linuxCaCertificatePaths) {
            try {
                const content = yield fs.promises.readFile(certPath, { encoding: 'utf8' });
                const certs = new Set(content.split(/(?=-----BEGIN CERTIFICATE-----)/g)
                    .filter(pem => !!pem.length));
                return Array.from(certs);
            }
            catch (err) {
                if ((err === null || err === void 0 ? void 0 : err.code) !== 'ENOENT') {
                    throw err;
                }
            }
        }
        return [];
    });
}
function derToPem(blob) {
    const lines = ['-----BEGIN CERTIFICATE-----'];
    const der = blob.toString('base64');
    for (let i = 0; i < der.length; i += 64) {
        lines.push(der.substr(i, 64));
    }
    lines.push('-----END CERTIFICATE-----', '');
    return lines.join(os.EOL);
}
function toErrorMessage(err) {
    return err && (err.stack || err.message) || String(err);
}
function toLogString(args) {
    return `[${args.map(arg => JSON.stringify(arg, (key, value) => {
        const t = typeof value;
        if (t === 'object') {
            if (key) {
                if ((key === 'ca' || key === '_vscodeAdditionalCaCerts' || key === 'testCertificates') && Array.isArray(value)) {
                    return `[${value.length} certs]`;
                }
                if (key === 'ca' && (typeof value === 'string' || Buffer.isBuffer(value))) {
                    return `[${(value.toString().match(/-----BEGIN CERTIFICATE-----/g) || []).length} certs]`;
                }
                return !value || value.toString ? String(value) : Object.prototype.toString.call(value);
            }
            else {
                return value;
            }
        }
        if (t === 'function') {
            return `[Function: ${value.name}]`;
        }
        if (t === 'bigint') {
            return String(value);
        }
        if (t === 'string' && value.length > 25) {
            const len = `[${value.length} chars]`;
            return `${value.substr(0, 25 - len.length)}${len}`;
        }
        return value;
    })).join(', ')}]`;
}
exports.toLogString = toLogString;
//# sourceMappingURL=index.js.map