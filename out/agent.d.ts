/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import http from 'http';
import { Readable, Duplex } from 'stream';
import { HttpProxyAgentOptions } from 'http-proxy-agent';
import { HttpsProxyAgentOptions } from 'https-proxy-agent';
import { SocksProxyAgentOptions } from 'socks-proxy-agent';
import { Agent, AgentConnectOpts } from 'agent-base';
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
export declare class PacProxyAgent extends Agent {
    resolver: FindProxyForURL;
    opts: PacProxyAgentOptions;
    addCAs: (opts: PacProxyAgentOptions) => Promise<void>;
    casAdded: boolean;
    cache?: Readable;
    constructor(resolver: FindProxyForURL, opts?: PacProxyAgentOptions, addCAs?: (opts: PacProxyAgentOptions) => Promise<void>);
    /**
     * Called when the node-core HTTP client library is creating a new HTTP request.
     *
     * @api protected
     */
    connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<Duplex | http.Agent>;
}
/**
 * Replaces credentials (userinfo) in proxy resolver result strings with a placeholder.
 * E.g., "PROXY user:pass@host:8080" → "PROXY <credentials>@host:8080"
 */
export declare function sanitizeProxyResultCredentials(result: string | undefined): string;
/**
 * The kind of proxy that was resolved for a URL, as reported by the PAC-style
 * resolver result (`DIRECT`, `PROXY`, `HTTP`, `HTTPS`, `SOCKS`, `SOCKS5`,
 * `SOCKS4`). Note `HTTP` and `PROXY` both denote an HTTP proxy, and `SOCKS`
 * denotes SOCKSv5. `EMPTY` means no result was returned at all (falsy) and
 * `UNRECOGNIZED` means a non-empty result was returned but none of its entries
 * used a known scheme; both are treated as a direct connection.
 */
export type ProxyResolveType = 'DIRECT' | 'PROXY' | 'HTTP' | 'HTTPS' | 'SOCKS' | 'SOCKS5' | 'SOCKS4' | 'EMPTY' | 'UNRECOGNIZED';
export declare function getProxyURLFromResolverResult(result: string | undefined): {
    proxy: string;
    url: string | undefined;
    type: ProxyResolveType;
};
type LookupProxyAuthorization = (proxyURL: string, proxyAuthenticate: string | string[] | undefined, state: Record<string, any>) => Promise<string | undefined>;
type HttpsProxyAgentOptions2<Uri> = HttpsProxyAgentOptions<Uri> & {
    lookupProxyAuthorization?: LookupProxyAuthorization;
};
export declare function createPacProxyAgent(resolver: FindProxyForURL, opts?: PacProxyAgentOptions, addCAs?: (opts: PacProxyAgentOptions) => Promise<void>): PacProxyAgent;
type PacProxyAgentOptions = HttpProxyAgentOptions<''> & HttpsProxyAgentOptions2<''> & SocksProxyAgentOptions & {
    fallbackToDirect?: boolean;
    originalAgent?: false | http.Agent;
    _vscodeTestReplaceCaCerts?: boolean;
    testCertificates?: (string | Buffer)[];
};
export {};
