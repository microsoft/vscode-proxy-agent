/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Nathan Rajlich, Félicien François, Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as net from 'net';
import * as http from 'http';
import type * as https from 'https';
import * as tls from 'tls';
import * as nodeurl from 'url';
import * as os from 'os';
import * as fs from 'fs';
import * as cp from 'child_process';
import * as crypto from 'crypto';
import * as undici from 'undici';
import * as stream from 'stream';

import { createPacProxyAgent, getProxyURLFromResolverResult, PacProxyAgent } from './agent';
import type { IncomingHttpHeaders } from 'undici/types/header';

export enum LogLevel {
	Trace,
	Debug,
	Info,
	Warning,
	Error,
	Critical,
	Off
}

export type ProxyResolveEvent = {
	count: number;
	duration: number;
	errorCount: number;
	cacheCount: number;
	cacheSize: number;
	cacheRolls: number;
	envCount: number;
	settingsCount: number;
	localhostCount: number;
	envNoProxyCount: number;
	configNoProxyCount: number;
	results: ConnectionResult[];
};

interface ConnectionResult {
	proxy: string;
	connection: string;
	code: string;
	count: number;
}

const maxCacheEntries = 5000; // Cache can grow twice that much due to 'oldCache'.

export type LookupProxyAuthorization = (proxyURL: string, proxyAuthenticate: string | string[] | undefined, state: Record<string, any>) => Promise<string | undefined>;

export interface Log {
	trace(message: string, ...args: any[]): void;
	debug(message: string, ...args: any[]): void;
	info(message: string, ...args: any[]): void;
	warn(message: string, ...args: any[]): void;
	error(message: string | Error, ...args: any[]): void;
}

export interface ProxyAgentParams {
	resolveProxy(url: string): Promise<string | undefined>;
	getProxyURL: () => string | undefined,
	getProxySupport: () => ProxySupportSetting,
	getNoProxyConfig?: () => string[],
	isAdditionalFetchSupportEnabled: () => boolean,
	addCertificatesV1: () => boolean,
	addCertificatesV2: () => boolean,
	loadAdditionalCertificates(): Promise<string[]>;
	lookupProxyAuthorization?: LookupProxyAuthorization;
	log: Log;
	getLogLevel(): LogLevel;
	proxyResolveTelemetry(event: ProxyResolveEvent): void;
	isUseHostProxyEnabled: () => boolean;
	env: NodeJS.ProcessEnv;
}

export function createProxyResolver(params: ProxyAgentParams) {
	const { getProxyURL, log, proxyResolveTelemetry: proxyResolverTelemetry, env } = params;
	let envProxy = proxyFromConfigURL(env.https_proxy || env.HTTPS_PROXY || env.http_proxy || env.HTTP_PROXY); // Not standardized.

	let envNoProxy = noProxyFromEnv(env.no_proxy || env.NO_PROXY); // Not standardized.

	let cacheRolls = 0;
	let oldCache = new Map<string, string>();
	let cache = new Map<string, string>();
	function getCacheKey(url: nodeurl.UrlWithStringQuery) {
		// Expecting proxies to usually be the same per scheme://host:port. Assuming that for performance.
		return nodeurl.format({ ...url, ...{ pathname: undefined, search: undefined, hash: undefined } });
	}
	function getCachedProxy(key: string) {
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
	function cacheProxy(key: string, proxy: string) {
		cache.set(key, proxy);
		if (cache.size >= maxCacheEntries) {
			oldCache = cache;
			cache = new Map();
			cacheRolls++;
			log.debug('ProxyResolver#cacheProxy cacheRolls', cacheRolls);
		}
	}

	let timeout: NodeJS.Timer | undefined;
	let count = 0;
	let duration = 0;
	let errorCount = 0;
	let cacheCount = 0;
	let envCount = 0;
	let settingsCount = 0;
	let localhostCount = 0;
	let envNoProxyCount = 0;
	let configNoProxyCount = 0;
	let results: ConnectionResult[] = [];
	function logEvent() {
		timeout = undefined;
		proxyResolverTelemetry({ count, duration, errorCount, cacheCount, cacheSize: cache.size, cacheRolls, envCount, settingsCount, localhostCount, envNoProxyCount, configNoProxyCount, results });
		count = duration = errorCount = cacheCount = envCount = settingsCount = localhostCount = envNoProxyCount = configNoProxyCount = 0;
		results = [];
	}

	function resolveProxyWithRequest(flags: { useProxySettings: boolean, addCertificatesV1: boolean }, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) {
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
		});
	}

	function useProxySettings(url: string, req: http.ClientRequest | undefined, stackText: string, callback: (proxy?: string) => void) {
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
		} else {
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
				const fallback: string | undefined = cache.values().next().value; // fall back to any proxy (https://github.com/microsoft/vscode/issues/122825)
				callback(fallback);
				log.error('ProxyResolver#resolveProxy', fallback, toErrorMessage(err), stackText);
			});
	}

	return {
		resolveProxyWithRequest,
		resolveProxyURL: (url: string) => new Promise<string | undefined>((resolve, reject) => {
			useProxySettings(url, undefined, '', result => {
				try {
					resolve(getProxyURLFromResolverResult(result).url);
				} catch (err) {
					reject(err);
				}
			});
		}),
	};
}

function collectResult(results: ConnectionResult[], resolveProxy: string, connection: string, req: http.ClientRequest) {
	const proxy = resolveProxy ? String(resolveProxy).trim().split(/\s+/, 1)[0] : 'EMPTY';
	req.on('response', res => {
		const code = `HTTP_${res.statusCode}`;
		const result = findOrCreateResult(results, proxy, connection, code);
		result.count++;
	});
	req.on('error', err => {
		const code = err && typeof (<any>err).code === 'string' && (<any>err).code || 'UNKNOWN_ERROR';
		const result = findOrCreateResult(results, proxy, connection, code);
		result.count++;
	});
}

function findOrCreateResult(results: ConnectionResult[], proxy: string, connection: string, code: string): ConnectionResult {
	for (const result of results) {
		if (result.proxy === proxy && result.connection === connection && result.code === code) {
			return result;
		}
	}
	const result = { proxy, connection, code, count: 0 };
	results.push(result);
	return result;
}

function proxyFromConfigURL(configURL: string | undefined) {
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
	} else if (scheme === 'https') {
		return 'HTTPS ' + proxy;
	} else if (scheme === 'socks' || scheme === 'socks5' || scheme === 'socks5h') {
		return 'SOCKS ' + proxy;
	} else if (scheme === 'socks4' || scheme === 'socks4a') {
		return 'SOCKS4 ' + proxy;
	}
	return undefined;
}

function shouldBypassProxy(value: string[]) {
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
	return (hostname: string, port: string) => filters.some(({ domain, port: filterPort }) => {
		return `.${hostname.toLowerCase()}`.endsWith(domain) && (!filterPort || port === filterPort);
	});
}

function noProxyFromEnv(envValue?: string) {
	const value = (envValue || '')
		.trim()
		.toLowerCase()
		.split(',');
	return shouldBypassProxy(value);
}

function noProxyFromConfig(noProxy: string[]) {
	const value = noProxy
		.map((item) => item.trim().toLowerCase());
	return shouldBypassProxy(value);
}

export type ProxySupportSetting = 'override' | 'fallback' | 'on' | 'off';

export type ResolveProxyWithRequest = (flags: { useProxySettings: boolean, addCertificatesV1: boolean }, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) => void;

export function createHttpPatch(params: ProxyAgentParams, originals: typeof http | typeof https, resolveProxy: ResolveProxyWithRequest) {
	return {
		get: patch(originals.get),
		request: patch(originals.request)
	};

	function patch(original: typeof http.get) {
		function patched(url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: (res: http.IncomingMessage) => void): http.ClientRequest {
			if (typeof url !== 'string' && !(url && (<any>url).searchParams)) {
				callback = <any>options;
				options = url;
				url = null;
			}
			if (typeof options === 'function') {
				callback = options;
				options = null;
			}
			options = options || {};

			if (options.socketPath) {
				return original.apply(null, arguments as any);
			}

			const originalAgent = options.agent;
			if (originalAgent === true) {
				throw new Error('Unexpected agent option: true');
			}
			const isHttps = (originals.globalAgent as any).protocol === 'https:';
			const optionsPatched = originalAgent instanceof PacProxyAgent;
			const config = params.getProxySupport();
			const useProxySettings = !optionsPatched && (config === 'override' || config === 'fallback' || (config === 'on' && originalAgent === undefined));
			// If Agent.options.ca is set to undefined, it overwrites RequestOptions.ca.
			const originalOptionsCa = isHttps ? (options as https.RequestOptions).ca : undefined;
			const originalAgentCa = isHttps && originalAgent instanceof originals.Agent && (originalAgent as https.Agent).options && 'ca' in (originalAgent as https.Agent).options && (originalAgent as https.Agent).options.ca;
			const originalAgentCheckServerIdentity = isHttps && originalAgent instanceof originals.Agent && (originalAgent as https.Agent).options && 'checkServerIdentity' in (originalAgent as https.Agent).options && (originalAgent as https.Agent).options.checkServerIdentity;
			const originalCheckServerIdentity = originalAgentCheckServerIdentity !== false ? originalAgentCheckServerIdentity : undefined;
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
					options = { ...urlOptions, ...options };
				} else {
					options = { ...options };
				}
				const resolveP = (req: http.ClientRequest, opts: http.RequestOptions, url: string): Promise<string | undefined> => new Promise<string | undefined>(resolve => resolveProxy({ useProxySettings, addCertificatesV1 }, req, opts, url, resolve));
				const host = options.hostname || options.host;
				const isLocalhost = !host || host === 'localhost' || host === '127.0.0.1'; // Avoiding https://github.com/microsoft/vscode/issues/120354
				const agent = createPacProxyAgent(resolveP, {
					originalAgent: (!useProxySettings || isLocalhost || config === 'fallback') ? originalAgent : undefined,
					lookupProxyAuthorization: params.lookupProxyAuthorization,
					// keepAlive: ((originalAgent || originals.globalAgent) as { keepAlive?: boolean }).keepAlive, // Skipping due to https://github.com/microsoft/vscode/issues/228872.
					checkServerIdentity: (host, cert) => originalCheckServerIdentity?.(host, cert),
					_vscodeTestReplaceCaCerts: (options as SecureContextOptionsPatch)._vscodeTestReplaceCaCerts,
				}, opts => new Promise<void>(resolve => addCertificatesToOptionsV1(params, params.addCertificatesV1(), opts, resolve)));
				agent.protocol = isHttps ? 'https:' : 'http:';
				options.agent = agent
				if (isHttps) {
					(options as https.RequestOptions).ca = originalCa;
				}
				return original(options, callback);
			}

			return original.apply(null, arguments as any);
		}
		return patched;
	}
}

export interface SecureContextOptionsPatch {
	_vscodeAdditionalCaCerts?: (string | Buffer)[];
	_vscodeTestReplaceCaCerts?: boolean;
}

export function createNetPatch(params: ProxyAgentParams, originals: typeof net) {
	return {
		connect: patchNetConnect(params, originals.connect),
	};
}

function patchNetConnect(params: ProxyAgentParams, original: typeof net.connect): typeof net.connect {
    function connect(options: net.NetConnectOpts, connectionListener?: () => void): net.Socket;
    function connect(port: number, host?: string, connectionListener?: () => void): net.Socket;
    function connect(path: string, connectionListener?: () => void): net.Socket;
	function connect(...args: any[]): net.Socket {
		if (params.getLogLevel() === LogLevel.Trace) {
			params.log.trace('ProxyResolver#net.connect', toLogString(args));
		}
		if (!params.addCertificatesV2()) {
			return original.apply(null, arguments as any);
		}
		const socket = new net.Socket();
		(socket as any).connecting = true;
		getOrLoadAdditionalCertificates(params)
			.then(() => {
				const options: net.NetConnectOpts | undefined = args.find(arg => arg && typeof arg === 'object');
				if (options?.timeout) {
					socket.setTimeout(options.timeout);
				}
				socket.connect.apply(socket, arguments as any);
			})
			.catch(err => {
				params.log.error('ProxyResolver#net.connect', toErrorMessage(err));
			});
		return socket;
	}
	return connect;
}

export function createTlsPatch(params: ProxyAgentParams, originals: typeof tls) {
	return {
		connect: patchTlsConnect(params, originals.connect),
		createSecureContext: patchCreateSecureContext(originals.createSecureContext),
	};
}

function patchTlsConnect(params: ProxyAgentParams, original: typeof tls.connect): typeof tls.connect {
	function connect(options: tls.ConnectionOptions, secureConnectListener?: () => void): tls.TLSSocket;
	function connect(port: number, host?: string, options?: tls.ConnectionOptions, secureConnectListener?: () => void): tls.TLSSocket;
	function connect(port: number, options?: tls.ConnectionOptions, secureConnectListener?: () => void): tls.TLSSocket;
	function connect(...args: any[]): tls.TLSSocket {
		if (params.getLogLevel() === LogLevel.Trace) {
			params.log.trace('ProxyResolver#tls.connect', toLogString(args));
		}
		let options: tls.ConnectionOptions | undefined = args.find(arg => arg && typeof arg === 'object');
		if (!params.addCertificatesV2() || options?.ca) {
			return original.apply(null, arguments as any);
		}
		let secureConnectListener: (() => void) | undefined = args.find(arg => typeof arg === 'function');
		if (!options) {
			options = {};
			const listenerIndex = args.findIndex(arg => typeof arg === 'function');
			if (listenerIndex !== -1) {
				args[listenerIndex - 1] = options;
			} else {
				args[2] = options;
			}
		} else {
			options = {
				...options
			};
		}
		const port = typeof args[0] === 'number' ? args[0]
			: typeof args[0] === 'string' && !isNaN(Number(args[0])) ? Number(args[0]) // E.g., http2 module passes port as string.
			: options.port;
		const host = typeof args[1] === 'string' ? args[1] : options.host;
		let tlsSocket: tls.TLSSocket;
		if (options.socket) {
			if (!options.secureContext) {
				options.secureContext = tls.createSecureContext(options);
			}
			if (!_certificates) {
				params.log.trace('ProxyResolver#tls.connect waiting for existing socket connect');
				options.socket.once('connect' , () => {
					params.log.trace('ProxyResolver#tls.connect got existing socket connect - adding certs');
					for (const cert of _certificates || []) {
						options!.secureContext!.context.addCACert(cert);
					}
				});
			} else {
				params.log.trace('ProxyResolver#tls.connect existing socket already connected - adding certs');
				for (const cert of _certificates) {
					options!.secureContext!.context.addCACert(cert);
				}
			}
		} else {
			if (!options.secureContext) {
				options.secureContext = tls.createSecureContext(options);
			}
			params.log.trace('ProxyResolver#tls.connect creating unconnected socket');
			const socket = options.socket = new net.Socket();
			(socket as any).connecting = true;
			getOrLoadAdditionalCertificates(params)
				.then(caCertificates => {
					params.log.trace('ProxyResolver#tls.connect adding certs before connecting socket');
					for (const cert of caCertificates) {
						options!.secureContext!.context.addCACert(cert);
					}
					if (options?.timeout) {
						socket.setTimeout(options.timeout);
						socket.once('timeout', () => {
							tlsSocket.emit('timeout');
						});
					}
					socket.connect({
						port: port!,
						host,
						...options,
					});
				})
				.catch(err => {
					params.log.error('ProxyResolver#tls.connect', toErrorMessage(err));
				});
		}
		if (typeof args[1] === 'string') {
			tlsSocket = original(port!, host!, options, secureConnectListener);
		} else if (typeof args[0] === 'number' || typeof args[0] === 'string' && !isNaN(Number(args[0]))) {
			tlsSocket = original(port!, options, secureConnectListener);
		} else {
			tlsSocket = original(options, secureConnectListener);
		}
		return tlsSocket;
	}
	return connect;
}

function patchCreateSecureContext(original: typeof tls.createSecureContext): typeof tls.createSecureContext {
	return function (details?: tls.SecureContextOptions): ReturnType<typeof tls.createSecureContext> {
		const context = original.apply(null, arguments as any);
		const certs = (details as SecureContextOptionsPatch)?._vscodeAdditionalCaCerts;
		if (certs) {
			for (const cert of certs) {
				context.context.addCACert(cert);
			}
		}
		return context;
	};
}

export function createFetchPatch(params: ProxyAgentParams, originalFetch: typeof globalThis.fetch, resolveProxyURL: (url: string) => Promise<string | undefined>) {
	return async function patchedFetch(input: string | URL | Request, init?: RequestInit) {
		if (!params.isAdditionalFetchSupportEnabled()) {
			return originalFetch(input, init);
		}
		const agentOptions = getAgentOptions(init);
		if (agentOptions.socketPath) {
			return originalFetch(input, init);
		}
		const proxySupport = params.getProxySupport();
		const doResolveProxy = proxySupport === 'override' || proxySupport === 'fallback' || (proxySupport === 'on' && ((init as any)?.dispatcher) === undefined);
		const addCerts = params.addCertificatesV1() || params.addCertificatesV2(); // There is no v2 for `fetch`, checking both settings.
		if (!doResolveProxy && !addCerts) {
			return originalFetch(input, init);
		}
		const urlString = typeof input === 'string' ? input : 'cache' in input ? input.url : input.toString();
		const proxyURL = doResolveProxy ? await resolveProxyURL(urlString) : undefined;
		if (!proxyURL && !addCerts) {
			return originalFetch(input, init);
		}
		const systemCA = addCerts ? [...tls.rootCertificates, ...await getOrLoadAdditionalCertificates(params)] : undefined;
		const { allowH2 } = agentOptions;
		const requestCA = agentOptions.requestCA || systemCA;
		const proxyCA = agentOptions.proxyCA || systemCA;
		if (!proxyURL) {
			const modifiedInit = {
				...init,
				dispatcher: new undici.Agent({
					allowH2,
					connect: { ca: requestCA },
				})
			};
			return originalFetch(input, modifiedInit);
		}

		const state: Record<string, any> = {};
		const proxyAuthorization = await params.lookupProxyAuthorization?.(proxyURL, undefined, state);
		const modifiedInit = {
			...init,
			dispatcher: new undici.ProxyAgent({
				uri: proxyURL,
				allowH2,
				headers: proxyAuthorization ? { 'Proxy-Authorization': proxyAuthorization } : undefined,
				requestTls: requestCA ? { allowH2, ca: requestCA } : { allowH2 },
				proxyTls: proxyCA ? { allowH2, ca: proxyCA } : { allowH2 },
				clientFactory: (origin: URL, opts: object): undici.Dispatcher => (new undici.Pool(origin, opts) as any).compose((dispatch: undici.Dispatcher['dispatch']) => {
					class ProxyAuthHandler extends undici.DecoratorHandler {
						constructor(private dispatch: undici.Dispatcher['dispatch'], private options: undici.Dispatcher.DispatchOptions, private handler: undici.Dispatcher.DispatchHandler) {
							super(handler);
						}
						onResponseError(controller: undici.Dispatcher.DispatchController, err: Error): void {
							if (!(err instanceof ProxyAuthError)) {
								return this.handler.onResponseError?.(controller, err);
							}
							(async () => {
								try {
									const proxyAuthorization = await params.lookupProxyAuthorization?.(proxyURL!, err.proxyAuthenticate, state);
									if (proxyAuthorization) {
										if (!this.options.headers) {
											this.options.headers = ['Proxy-Authorization', proxyAuthorization];
										} else if (Array.isArray(this.options.headers)) {
											const i = this.options.headers.findIndex((value, index) => index % 2 === 0 && value.toLowerCase() === 'proxy-authorization');
											if (i === -1) {
												this.options.headers.push('Proxy-Authorization', proxyAuthorization);
											} else {
												this.options.headers[i + 1] = proxyAuthorization;
											}
										} else if (typeof (this.options.headers as any)[Symbol.iterator] === 'function') {
											const headers = [...(this.options.headers as Iterable<[string, string | string[] | undefined]>)];
											const i = headers.findIndex(value => value[0].toLowerCase() === 'proxy-authorization');
											if (i === -1) {
												headers.push(['Proxy-Authorization', proxyAuthorization]);
											} else {
												headers[i][1] = proxyAuthorization;
											}
											this.options.headers = headers;
										} else {
											(this.options.headers as Record<string, string | string[] | undefined>)['Proxy-Authorization'] = proxyAuthorization;
										}
										this.dispatch(this.options, this);
									} else {
										this.handler.onResponseError?.(controller, new undici.errors.RequestAbortedError(`Proxy response (407) ?.== 200 when HTTP Tunneling`)); // Mimick undici's behavior
									}
								} catch (err: any) {
									this.handler.onResponseError?.(controller, err);
								}
							})();
						}
						onRequestUpgrade?(controller: undici.Dispatcher.DispatchController, statusCode: number, headers: IncomingHttpHeaders, socket: stream.Duplex): void {
							if (statusCode === 407 && headers) {
								let proxyAuthenticate: string | string[] | undefined;
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
							this.handler.onRequestUpgrade?.(controller, statusCode, headers, socket);
						}
					}
					return function proxyAuthDispatch(options: undici.Dispatcher.DispatchOptions, handler: undici.Dispatcher.DispatchHandler) {
						return dispatch(options, new ProxyAuthHandler(dispatch, options, handler));
					};
				}),
			})
		};
		return originalFetch(input, modifiedInit);
	};
}

class ProxyAuthError extends Error {
	constructor(public proxyAuthenticate: string | string[]) {
		super('Proxy authentication required');
	}
}

const agentOptions = Symbol('agentOptions');
const proxyAgentOptions = Symbol('proxyAgentOptions');

export function patchUndici(originalUndici: typeof undici) {
	const originalAgent = originalUndici.Agent;
	const patchedAgent = function PatchedAgent(opts?: undici.Agent.Options): undici.Agent {
		const agent = new originalAgent(opts);
		(agent as any)[agentOptions] = {
			...opts,
			...(opts?.connect && typeof opts?.connect === 'object' ? { connect: { ...opts.connect } } : undefined),
		};
		return agent;
	};
	patchedAgent.prototype = originalAgent.prototype;
	(originalUndici as any).Agent = patchedAgent;

	const originalProxyAgent = originalUndici.ProxyAgent;
	const patchedProxyAgent = function PatchedProxyAgent(opts: undici.ProxyAgent.Options | string): undici.ProxyAgent {
		const proxyAgent = new originalProxyAgent(opts);
		(proxyAgent as any)[proxyAgentOptions] = typeof opts === 'string' ? opts : {
			...opts,
			...(opts?.connect && typeof opts?.connect === 'object' ? { connect: { ...opts.connect } } : undefined),
		};
		return proxyAgent;
	};
	patchedProxyAgent.prototype = originalProxyAgent.prototype;
	(originalUndici as any).ProxyAgent = patchedProxyAgent;
}

function getAgentOptions(requestInit: RequestInit | undefined) {
	let allowH2: boolean | undefined;
	let requestCA: string | Buffer | Array<string | Buffer> | undefined;
	let proxyCA: string | Buffer | Array<string | Buffer> | undefined;
	let socketPath: string | undefined;
	const dispatcher: undici.Dispatcher = (requestInit as any)?.dispatcher;
	let originalAgentOptions: undici.Agent.Options | undefined = dispatcher && (dispatcher as any)[agentOptions];
	if (dispatcher && !originalAgentOptions) {
		// Handles bundled extension code where undici does not get patched.
		const optionsSymbol = Object.getOwnPropertySymbols(dispatcher).find(s => s.description === 'options');
		if (optionsSymbol) {
			originalAgentOptions = (dispatcher as any)[optionsSymbol];
		}
	}
	if (originalAgentOptions && typeof originalAgentOptions === 'object') {
		allowH2 = originalAgentOptions.allowH2;
		if (originalAgentOptions.connect && typeof originalAgentOptions.connect === 'object') {
			requestCA = 'ca' in originalAgentOptions.connect && originalAgentOptions.connect.ca || undefined;
			socketPath = originalAgentOptions.connect.socketPath || undefined;
		}
	}
	let originalProxyAgentOptions: undici.ProxyAgent.Options | string | undefined = dispatcher && (dispatcher as any)[proxyAgentOptions];
	if (dispatcher && !originalProxyAgentOptions) {
		// Handles bundled extension code where undici does not get patched.
		const proxyAgentSymbol = Object.getOwnPropertySymbols(dispatcher).find(s => s.description === 'proxy agent');
		if (proxyAgentSymbol) {
			const proxyAgent = (dispatcher as any)[proxyAgentSymbol];
			if (proxyAgent && typeof proxyAgent === 'object') {
				const optionsSymbol = Object.getOwnPropertySymbols(proxyAgent).find(s => s.description === 'options');
				if (optionsSymbol) {
					originalProxyAgentOptions = (proxyAgent as any)[optionsSymbol];
				}
			}
		}
	}
	if (originalProxyAgentOptions && typeof originalProxyAgentOptions === 'object') {
		allowH2 = originalProxyAgentOptions.allowH2;
		requestCA = originalProxyAgentOptions.requestTls && 'ca' in originalProxyAgentOptions.requestTls && originalProxyAgentOptions.requestTls.ca || undefined;
		proxyCA = originalProxyAgentOptions.proxyTls && 'ca' in originalProxyAgentOptions.proxyTls && originalProxyAgentOptions.proxyTls.ca || undefined;
	}
	return { allowH2, requestCA, proxyCA, socketPath };
}

function addCertificatesToOptionsV1(params: ProxyAgentParams, addCertificatesV1: boolean, opts: http.RequestOptions | tls.ConnectionOptions, callback: () => void) {
	if (addCertificatesV1) {
		getOrLoadAdditionalCertificates(params)
			.then(caCertificates => {
				if ((opts as SecureContextOptionsPatch)._vscodeTestReplaceCaCerts) {
					(opts as https.RequestOptions).ca = caCertificates;
				} else {
					(opts as SecureContextOptionsPatch)._vscodeAdditionalCaCerts = caCertificates;
				}
				callback();
			})
			.catch(err => {
				params.log.error('ProxyResolver#addCertificatesV1', toErrorMessage(err));
			});
	} else {
		callback();
	}
}

let _certificatesPromise: Promise<string[]> | undefined;
let _certificates: string[] | undefined;
export async function getOrLoadAdditionalCertificates(params: ProxyAgentParams) {
	if (!_certificatesPromise) {
		_certificatesPromise = (async () => {
			return _certificates = await params.loadAdditionalCertificates();
		})();
	}
	return _certificatesPromise;
}

export interface CertificateParams {
	log: Log;
}

let _systemCertificatesPromise: Promise<string[]> | undefined;
export async function loadSystemCertificates(params: CertificateParams) {
	if (!_systemCertificatesPromise) {
		_systemCertificatesPromise = (async () => {
			try {
				const certs = await readSystemCertificates();
				params.log.debug('ProxyResolver#loadSystemCertificates count', certs.length);
				const now = Date.now();
				const filtered = certs
					.filter(cert => {
						try {
							const parsedCert = new crypto.X509Certificate(cert);
							const parsedDate = Date.parse(parsedCert.validTo);
							return isNaN(parsedDate) || parsedDate > now;
						} catch (err) {
							params.log.debug('ProxyResolver#loadSystemCertificates parse error', toErrorMessage(err));
							return false;
						}
					});
				params.log.debug('ProxyResolver#loadSystemCertificates count filtered', filtered.length);
				return filtered;
			} catch (err) {
				params.log.error('ProxyResolver#loadSystemCertificates error', toErrorMessage(err));
				return [];
			}
		})();
	}
	return _systemCertificatesPromise;
}

export function resetCaches() {
	_certificatesPromise = undefined;
	_certificates = undefined;
	_systemCertificatesPromise = undefined;
}

async function readSystemCertificates(): Promise<string[]> {
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
}

async function readWindowsCaCertificates() {
	// @ts-ignore Windows only
	const winCA = await import('@vscode/windows-ca-certs');

	let ders: any[] = [];
	const store = new winCA.Crypt32();
	try {
		let der: any;
		while (der = store.next()) {
			ders.push(der);
		}
	} finally {
		store.done();
	}

	const certs = new Set(ders.map(derToPem));
	return Array.from(certs);
}

async function readMacCaCertificates() {
	const stdout = await new Promise<string>((resolve, reject) => {
		const child = cp.spawn('/usr/bin/security', ['find-certificate', '-a', '-p']);
		const stdout: string[] = [];
		child.stdout.setEncoding('utf8');
		child.stdout.on('data', str => stdout.push(str));
		child.on('error', reject);
		child.on('exit', code => code ? reject(code) : resolve(stdout.join('')));
	});
	const certs = new Set(stdout.split(/(?=-----BEGIN CERTIFICATE-----)/g)
		.filter(pem => !!pem.length));
	return Array.from(certs);
}

const linuxCaCertificatePaths = [
	'/etc/ssl/certs/ca-certificates.crt', // Debian / Ubuntu / Alpine / Fedora
	'/etc/ssl/certs/ca-bundle.crt', // Fedora
	'/etc/ssl/ca-bundle.pem', // OpenSUSE
];

async function readLinuxCaCertificates() {
	for (const certPath of linuxCaCertificatePaths) {
		try {
			const content = await fs.promises.readFile(certPath, { encoding: 'utf8' });
			const certs = new Set(content.split(/(?=-----BEGIN CERTIFICATE-----)/g)
				.filter(pem => !!pem.length));
			return Array.from(certs);
		} catch (err: any) {
			if (err?.code !== 'ENOENT') {
				throw err;
			}
		}
	}
	return [];
}

function derToPem(blob: Buffer) {
	const lines = ['-----BEGIN CERTIFICATE-----'];
	const der = blob.toString('base64');
	for (let i = 0; i < der.length; i += 64) {
		lines.push(der.substr(i, 64));
	}
	lines.push('-----END CERTIFICATE-----', '');
	return lines.join(os.EOL);
}

function toErrorMessage(err: any) {
	return err && (err.stack || err.message) || String(err);
}

export function toLogString(args: any[]) {
	return `[${args.map(arg => JSON.stringify(arg, (key, value) => {
			const t = typeof value;
			if (t === 'object') {
				if (key) {
					if ((key === 'ca' || key === '_vscodeAdditionalCaCerts') && Array.isArray(value)) {
						return `[${value.length} certs]`;
					}
					if (key === 'ca' && (typeof value === 'string' || Buffer.isBuffer(value))) {
						return `[${(value.toString().match(/-----BEGIN CERTIFICATE-----/g) || []).length} certs]`;
					}
					return !value || value.toString ? String(value) : Object.prototype.toString.call(value);
				} else {
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

/**
 * Certificates for testing. These are not automatically used, but can be added in
 * ProxyAgentParams#loadAdditionalCertificates(). This just provides a shared array
 * between production code and tests.
 */
export const testCertificates: string[] = [];
