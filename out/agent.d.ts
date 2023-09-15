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
declare class _PacProxyAgent extends Agent {
    resolver: FindProxyForURL;
    opts: createPacProxyAgent.PacProxyAgentOptions;
    cache?: Readable;
    constructor(resolver: FindProxyForURL, opts?: createPacProxyAgent.PacProxyAgentOptions);
    /**
     * Called when the node-core HTTP client library is creating a new HTTP request.
     *
     * @api protected
     */
    connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<Duplex | http.Agent>;
}
type LookupProxyAuthorization = (proxyURL: string, proxyAuthenticate: string | string[] | undefined, state: Record<string, any>) => Promise<string | undefined>;
type HttpsProxyAgentOptions2<Uri> = HttpsProxyAgentOptions<Uri> & {
    lookupProxyAuthorization?: LookupProxyAuthorization;
};
declare function createPacProxyAgent(resolver: FindProxyForURL, opts?: createPacProxyAgent.PacProxyAgentOptions): _PacProxyAgent;
declare namespace createPacProxyAgent {
    type PacProxyAgentOptions = HttpProxyAgentOptions<''> & HttpsProxyAgentOptions2<''> & SocksProxyAgentOptions & {
        fallbackToDirect?: boolean;
        originalAgent?: false | http.Agent;
    };
    type PacProxyAgent = _PacProxyAgent;
    const PacProxyAgent: typeof _PacProxyAgent;
}
export = createPacProxyAgent;
