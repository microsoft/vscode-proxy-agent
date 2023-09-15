/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import * as net from 'net';
import * as http from 'http';
import type * as https from 'https';
import * as tls from 'tls';
import * as nodeurl from 'url';
export declare enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    Off = 6
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
export type LookupProxyAuthorization = (proxyURL: string, proxyAuthenticate: string | string[] | undefined, state: Record<string, any>) => Promise<string | undefined>;
export interface ProxyAgentParams {
    resolveProxy(url: string): Promise<string | undefined>;
    getProxyURL: () => string | undefined;
    getProxySupport: () => ProxySupportSetting;
    getSystemCertificatesV1: () => boolean;
    getSystemCertificatesV2: () => boolean;
    lookupProxyAuthorization?: LookupProxyAuthorization;
    log(level: LogLevel, message: string, ...args: any[]): void;
    getLogLevel(): LogLevel;
    proxyResolveTelemetry(event: ProxyResolveEvent): void;
    useHostProxy: boolean;
    addCertificates: (string | Buffer)[];
    env: NodeJS.ProcessEnv;
}
export declare function createProxyResolver(params: ProxyAgentParams): (flags: {
    useProxySettings: boolean;
    useSystemCertificates: boolean;
}, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) => void;
export type ProxySupportSetting = 'override' | 'fallback' | 'on' | 'off';
export declare function createHttpPatch(params: ProxyAgentParams, originals: typeof http | typeof https, resolveProxy: ReturnType<typeof createProxyResolver>): {
    get: (url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: ((res: http.IncomingMessage) => void) | undefined) => http.ClientRequest;
    request: (url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: ((res: http.IncomingMessage) => void) | undefined) => http.ClientRequest;
};
export interface SecureContextOptionsPatch {
    _vscodeAdditionalCaCerts?: (string | Buffer)[];
}
export declare function createNetPatch(params: ProxyAgentParams, originals: typeof net): {
    connect: typeof net.connect;
};
export declare function createTlsPatch(params: ProxyAgentParams, originals: typeof tls): {
    connect: typeof tls.connect;
    createSecureContext: typeof tls.createSecureContext;
};
declare function useSystemCertificates(params: ProxyAgentParams, useSystemCertificates: boolean, opts: http.RequestOptions, callback: () => void): void;
export declare function resetCaches(): void;
export {};
