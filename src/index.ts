/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Nathan Rajlich, Félicien François, Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as http from 'http';
import type * as https from 'https';
import * as tls from 'tls';
import * as nodeurl from 'url';
import * as os from 'os';
import * as fs from 'fs';
import * as cp from 'child_process';

import debug from 'debug';
import createPacProxyAgent, { PacProxyAgent } from './agent';
const SocksProxyAgent = require('socks-proxy-agent');

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
	results: ConnectionResult[];
};

interface ConnectionResult {
	proxy: string;
	connection: string;
	code: string;
	count: number;
}

const maxCacheEntries = 5000; // Cache can grow twice that much due to 'oldCache'.

export interface ProxyAgentParams {
	resolveProxy(url: string): Promise<string | undefined>;
	getHttpProxySetting(): string | undefined;
	log(level: LogLevel, message: string, ...args: any[]): void;
	getLogLevel(): LogLevel;
	proxyResolveTelemetry(event: ProxyResolveEvent): void;
	useHostProxy: boolean;
	env: NodeJS.ProcessEnv;
}

export function createProxyResolver(params: ProxyAgentParams) {
	const { getHttpProxySetting, log, getLogLevel, proxyResolveTelemetry: proxyResolverTelemetry, useHostProxy, env } = params;
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
			log(LogLevel.Debug, 'ProxyResolver#cacheProxy cacheRolls', cacheRolls);
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
	let results: ConnectionResult[] = [];
	function logEvent() {
		timeout = undefined;
		proxyResolverTelemetry({ count, duration, errorCount, cacheCount, cacheSize: cache.size, cacheRolls, envCount, settingsCount, localhostCount, envNoProxyCount, results });
		count = duration = errorCount = cacheCount = envCount = settingsCount = localhostCount = envNoProxyCount = 0;
		results = [];
	}

	function resolveProxy(flags: { useProxySettings: boolean, useSystemCertificates: boolean }, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) {
		if (!timeout) {
			timeout = setTimeout(logEvent, 10 * 60 * 1000);
		}

		const stackText = getLogLevel() === LogLevel.Trace ? '\n' + new Error('Error for stack trace').stack : '';

		useSystemCertificates(params, flags.useSystemCertificates, opts, () => {
			useProxySettings(useHostProxy, flags.useProxySettings, req, opts, url, stackText, callback);
		});
	}

	function useProxySettings(useHostProxy: boolean, useProxySettings: boolean, req: http.ClientRequest, opts: http.RequestOptions, url: string, stackText: string, callback: (proxy?: string) => void) {

		if (!useProxySettings) {
			callback('DIRECT');
			return;
		}

		const parsedUrl = nodeurl.parse(url); // Coming from Node's URL, sticking with that.

		const hostname = parsedUrl.hostname;
		if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '::ffff:127.0.0.1') {
			localhostCount++;
			callback('DIRECT');
			log(LogLevel.Debug, 'ProxyResolver#resolveProxy localhost', url, 'DIRECT', stackText);
			return;
		}

		const { secureEndpoint } = opts as any;
		const defaultPort = secureEndpoint ? 443 : 80;
		if (typeof hostname === 'string' && envNoProxy(hostname, String(parsedUrl.port || defaultPort))) {
			envNoProxyCount++;
			callback('DIRECT');
			log(LogLevel.Debug, 'ProxyResolver#resolveProxy envNoProxy', url, 'DIRECT', stackText);
			return;
		}

		let settingsProxy = proxyFromConfigURL(getHttpProxySetting());
		if (settingsProxy) {
			settingsCount++;
			callback(settingsProxy);
			log(LogLevel.Debug, 'ProxyResolver#resolveProxy settings', url, settingsProxy, stackText);
			return;
		}

		if (envProxy) {
			envCount++;
			callback(envProxy);
			log(LogLevel.Debug, 'ProxyResolver#resolveProxy env', url, envProxy, stackText);
			return;
		}

		const key = getCacheKey(parsedUrl);
		const proxy = getCachedProxy(key);
		if (proxy) {
			cacheCount++;
			collectResult(results, proxy, parsedUrl.protocol === 'https:' ? 'HTTPS' : 'HTTP', req);
			callback(proxy);
			log(LogLevel.Debug, 'ProxyResolver#resolveProxy cached', url, proxy, stackText);
			return;
		}

		if (!useHostProxy) {
			callback('DIRECT');
			log(LogLevel.Debug, 'ProxyResolver#resolveProxy unconfigured', url, 'DIRECT', stackText);
			return;
		}

		const start = Date.now();
		params.resolveProxy(url) // Use full URL to ensure it is an actually used one.
			.then(proxy => {
				if (proxy) {
					cacheProxy(key, proxy);
					collectResult(results, proxy, parsedUrl.protocol === 'https:' ? 'HTTPS' : 'HTTP', req);
				}
				callback(proxy);
				log(LogLevel.Debug, 'ProxyResolver#resolveProxy', url, proxy, stackText);
			}).then(() => {
				count++;
				duration = Date.now() - start + duration;
			}, err => {
				errorCount++;
				const fallback: string | undefined = cache.values().next().value; // fall back to any proxy (https://github.com/microsoft/vscode/issues/122825)
				callback(fallback);
				log(LogLevel.Error, 'ProxyResolver#resolveProxy', fallback, toErrorMessage(err), stackText);
			});
	}

	return resolveProxy;
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
	} else if (scheme === 'socks') {
		return 'SOCKS ' + proxy;
	}
	return undefined;
}

function noProxyFromEnv(envValue?: string) {
	const value = (envValue || '')
		.trim()
		.toLowerCase();

	if (value === '*') {
		return () => true;
	}

	const filters = value
		.split(',')
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

export type ProxySupportSetting = 'override' | 'fallback' | 'on' | 'off';

export function createHttpPatch(originals: typeof http | typeof https, resolveProxy: ReturnType<typeof createProxyResolver>, proxySetting: { config: ProxySupportSetting }, certSetting: { config: boolean }, onRequest: boolean) {
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
			const config: ProxySupportSetting = onRequest && ((<any>options)._vscodeProxySupport || /* LS */ (<any>options)._vscodeSystemProxy) || proxySetting.config;
			const useProxySettings = !optionsPatched && (config === 'override' || config === 'fallback' || (config === 'on' && originalAgent === undefined));
			const useSystemCertificates = !optionsPatched && certSetting.config && isHttps && !(options as https.RequestOptions).ca;

			if (useProxySettings || useSystemCertificates) {
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
				const resolveP = (req: http.ClientRequest, opts: http.RequestOptions, url: string): Promise<string | undefined> => new Promise<string | undefined>(resolve => resolveProxy({ useProxySettings, useSystemCertificates }, req, opts, url, resolve));
				const host = options.hostname || options.host;
				const isLocalhost = !host || host === 'localhost' || host === '127.0.0.1'; // Avoiding https://github.com/microsoft/vscode/issues/120354
				options.agent = createPacProxyAgent(resolveP, { originalAgent: (!useProxySettings || isLocalhost || config === 'fallback') ? originalAgent : undefined })
				return original(options, callback);
			}

			return original.apply(null, arguments as any);
		}
		return patched;
	}
}

export interface SecureContextOptionsPatch {
	_vscodeAdditionalCaCerts?: string[];
}

export function createTlsPatch(originals: typeof tls) {
	return {
		createSecureContext: patchCreateSecureContext(originals.createSecureContext),
	};
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

function useSystemCertificates(params: ProxyAgentParams, useSystemCertificates: boolean, opts: http.RequestOptions, callback: () => void) {
	if (useSystemCertificates) {
		getCaCertificates(params)
			.then(caCertificates => {
				if (caCertificates) {
					if (caCertificates.append) {
						(opts as SecureContextOptionsPatch)._vscodeAdditionalCaCerts = caCertificates.certs;
					} else {
						(opts as https.RequestOptions).ca = caCertificates.certs;
					}
				}
				callback();
			})
			.catch(err => {
				params.log(LogLevel.Error, 'ProxyResolver#useSystemCertificates', toErrorMessage(err));
			});
	} else {
		callback();
	}
}

let _caCertificates: ReturnType<typeof readCaCertificates> | Promise<undefined>;
async function getCaCertificates({ log }: ProxyAgentParams) {
	if (!_caCertificates) {
		_caCertificates = readCaCertificates()
			.then(res => {
				log(LogLevel.Debug, 'ProxyResolver#getCaCertificates count', res && res.certs.length);
				return res && res.certs.length ? res : undefined;
			})
			.catch(err => {
				log(LogLevel.Error, 'ProxyResolver#getCaCertificates error', toErrorMessage(err));
				return undefined;
			});
	}
	return _caCertificates;
}

async function readCaCertificates() {
	if (process.platform === 'win32') {
		return readWindowsCaCertificates();
	}
	if (process.platform === 'darwin') {
		return readMacCaCertificates();
	}
	if (process.platform === 'linux') {
		return readLinuxCaCertificates();
	}
	return undefined;
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
	return {
		certs: Array.from(certs),
		append: true
	};
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
	return {
		certs: Array.from(certs),
		append: true
	};
}

const linuxCaCertificatePaths = [
	'/etc/ssl/certs/ca-certificates.crt',
	'/etc/ssl/certs/ca-bundle.crt',
];

async function readLinuxCaCertificates() {
	for (const certPath of linuxCaCertificatePaths) {
		try {
			const content = await fs.promises.readFile(certPath, { encoding: 'utf8' });
			const certs = new Set(content.split(/(?=-----BEGIN CERTIFICATE-----)/g)
				.filter(pem => !!pem.length));
			return {
				certs: Array.from(certs),
				append: false
			};
		} catch (err: any) {
			if (err?.code !== 'ENOENT') {
				throw err;
			}
		}
	}
	return undefined;
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
