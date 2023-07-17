import http from 'http';
import https from 'https';
import net from 'net';
import createDebug from 'debug';
import { Readable, Duplex } from 'stream';
import { format, parse } from 'url';
import { HttpProxyAgent, HttpProxyAgentOptions } from 'http-proxy-agent';
import { HttpsProxyAgent, HttpsProxyAgentOptions } from 'https-proxy-agent';
import { SocksProxyAgent, SocksProxyAgentOptions } from 'socks-proxy-agent';
import {
	Agent,
	AgentConnectOpts,
} from 'agent-base';
import EventEmitter from 'events';

const debug = createDebug('pac-proxy-agent');

type FindProxyForURL = (req: http.ClientRequest, opts: http.RequestOptions, url: string) => Promise<string | undefined>;

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
class _PacProxyAgent extends Agent {
	resolver: FindProxyForURL;
	opts: createPacProxyAgent.PacProxyAgentOptions;
	cache?: Readable;

	constructor(resolver: FindProxyForURL, opts: createPacProxyAgent.PacProxyAgentOptions = {}) {
		super(opts);
		debug('Creating PacProxyAgent with options %o', opts);

		this.resolver = resolver;
		this.opts = { ...opts };
		this.cache = undefined;
	}

	/**
	 * Called when the node-core HTTP client library is creating a new HTTP request.
	 *
	 * @api protected
	 */
	async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<Duplex | http.Agent> {
		const { secureEndpoint } = opts;

		// Calculate the `url` parameter
		const defaultPort = secureEndpoint ? 443 : 80;
		let path = req.path;
		let search: string | null = null;
		const firstQuestion = path.indexOf('?');
		if (firstQuestion !== -1) {
			search = path.substring(firstQuestion);
			path = path.substring(0, firstQuestion);
		}

		const urlOpts = {
			...opts,
			protocol: secureEndpoint ? 'https:' : 'http:',
			pathname: path,
			search,

			// need to use `hostname` instead of `host` otherwise `port` is ignored
			hostname: opts.host,
			host: null,
			href: null,

			// set `port` to null when it is the protocol default port (80 / 443)
			port: defaultPort === opts.port ? null : opts.port
		};
		const url = format(urlOpts);

		debug('url: %o', url);
		let result = await this.resolver(req, opts, url);

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
			let agent: http.Agent | null = null;
			const [type, target] = proxy.split(/\s+/);
			debug('Attempting to use proxy: %o', proxy);

			if (type === 'DIRECT') {
				// Needed for SNI.
				const originalAgent = this.opts.originalAgent;
				const defaultAgent = secureEndpoint ? https.globalAgent : http.globalAgent;
				agent = originalAgent === false ? new (defaultAgent as any).constructor() : (originalAgent || defaultAgent)
			} else if (type === 'SOCKS' || type === 'SOCKS5') {
				// Use a SOCKSv5h proxy
				agent = new SocksProxyAgent(`socks://${target}`);
			} else if (type === 'SOCKS4') {
				// Use a SOCKSv4a proxy
				agent = new SocksProxyAgent(`socks4a://${target}`);
			} else if (
				type === 'PROXY' ||
				type === 'HTTP' ||
				type === 'HTTPS'
			) {
				// Use an HTTP or HTTPS proxy
				// http://dev.chromium.org/developers/design-documents/secure-web-proxy
				const proxyURL = `${
					type === 'HTTPS' ? 'https' : 'http'
				}://${target}`;
				if (secureEndpoint) {
					agent = new HttpsProxyAgent2(proxyURL, this.opts);
				} else {
					agent = new HttpProxyAgent(proxyURL, this.opts);
				}
			}

			try {
				if (agent) {
					let s: Duplex | http.Agent;
					if (agent instanceof Agent) {
						s = await agent.connect(req, opts);
					} else {
						s = agent;
					}
					req.emit('proxy', { proxy, socket: s });
					return s;
				}
				throw new Error(`Could not determine proxy type for: ${proxy}`);
			} catch (err) {
				debug('Got error for proxy %o: %o', proxy, err);
				req.emit('proxy', { proxy, error: err });
			}
		}

		throw new Error(
			`Failed to establish a socket connection to proxies: ${JSON.stringify(
				proxies
			)}`
		);
	}
}

type LookupProxyAuthorization = (proxyURL: string, proxyAuthenticate?: string) => Promise<string | undefined>; 

type HttpsProxyAgentOptions2<Uri> = HttpsProxyAgentOptions<Uri> & { lookupProxyAuthorization?: LookupProxyAuthorization };

interface ConnectResponse {
	statusCode: number;
	statusText: string;
	headers: http.IncomingHttpHeaders;
}

class HttpsProxyAgent2<Uri extends string> extends HttpsProxyAgent<Uri> {

	addHeaders: http.OutgoingHttpHeaders;
	lookupProxyAuthorization?: LookupProxyAuthorization;

	constructor(proxy: Uri | URL, opts: HttpsProxyAgentOptions2<Uri>) {
		const addHeaders = {};
		const origHeaders = opts?.headers;
		const agentOpts: HttpsProxyAgentOptions<Uri> = {
			...opts,
			headers: (): http.OutgoingHttpHeaders => {
				const headers = origHeaders
					? typeof origHeaders === 'function'
						? origHeaders()
						: origHeaders
					: {};
				return {
					...headers,
					...addHeaders
				};
			}
		};
		super(proxy, agentOpts);
		this.addHeaders = addHeaders;
		this.lookupProxyAuthorization = opts.lookupProxyAuthorization;
	}

	async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<net.Socket> {
		const tmpReq = new EventEmitter();
		let connect: ConnectResponse | undefined;
		tmpReq.once('proxyConnect', (_connect: ConnectResponse) => {
			connect = _connect;
		});
		if (this.lookupProxyAuthorization) {
			try {
				const proxyAuthorization = await this.lookupProxyAuthorization(this.proxy.href);
				if (proxyAuthorization) {
					this.addHeaders['Proxy-Authorization'] = proxyAuthorization;
				}
			} catch (err) {
				req.emit('error', err);
			}
		}
		const s = await super.connect(tmpReq as any, opts);
		if (this.lookupProxyAuthorization && connect?.statusCode === 407 && connect.headers['proxy-authenticate']) {
			try {
				const proxyAuthorization = await this.lookupProxyAuthorization(this.proxy.href, connect.headers['proxy-authenticate']);
				if (proxyAuthorization) {
					this.addHeaders['Proxy-Authorization'] = proxyAuthorization;
					tmpReq.removeAllListeners();
					s.destroy();
					return this.connect(req, opts);
				}
			} catch (err) {
				req.emit('error', err);
			}
		}
		req.once('socket', s => tmpReq.emit('socket', s));
		return s;
	}
}

function createPacProxyAgent(
	resolver: FindProxyForURL,
	opts?: createPacProxyAgent.PacProxyAgentOptions
): _PacProxyAgent {
	if (!opts) {
		opts = {};
	}

	if (typeof resolver !== 'function') {
		throw new TypeError('a resolve function must be specified!');
	}

	return new _PacProxyAgent(resolver, opts);
}

namespace createPacProxyAgent {
	export type PacProxyAgentOptions =
			HttpProxyAgentOptions<''> &
			HttpsProxyAgentOptions2<''> &
			SocksProxyAgentOptions & {
		fallbackToDirect?: boolean;
		originalAgent?: false | http.Agent;
	}

	export type PacProxyAgent = _PacProxyAgent;
	export const PacProxyAgent = _PacProxyAgent;

	createPacProxyAgent.prototype = _PacProxyAgent.prototype;
}

export = createPacProxyAgent;