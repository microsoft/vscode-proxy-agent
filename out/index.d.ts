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
import * as undici from 'undici';
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
    configNoProxyCount: number;
    results: ConnectionResult[];
};
interface ConnectionResult {
    proxy: string;
    connection: string;
    code: string;
    count: number;
}
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
    getProxyURL: () => string | undefined;
    getProxySupport: () => ProxySupportSetting;
    getNoProxyConfig?: () => string[];
    isAdditionalFetchSupportEnabled: () => boolean;
    addCertificatesV1: () => boolean;
    addCertificatesV2: () => boolean;
    loadAdditionalCertificates(): Promise<string[]>;
    lookupProxyAuthorization?: LookupProxyAuthorization;
    log: Log;
    getLogLevel(): LogLevel;
    proxyResolveTelemetry(event: ProxyResolveEvent): void;
    useHostProxy: boolean;
    env: NodeJS.ProcessEnv;
}
export declare function createProxyResolver(params: ProxyAgentParams): {
    resolveProxyWithRequest: (flags: {
        useProxySettings: boolean;
        addCertificatesV1: boolean;
    }, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) => void;
    resolveProxyURL: (url: string) => Promise<string | undefined>;
};
export type ProxySupportSetting = 'override' | 'fallback' | 'on' | 'off';
export type ResolveProxyWithRequest = (flags: {
    useProxySettings: boolean;
    addCertificatesV1: boolean;
}, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) => void;
export declare function createHttpPatch(params: ProxyAgentParams, originals: typeof http | typeof https, resolveProxy: ResolveProxyWithRequest): {
    get: (url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: ((res: http.IncomingMessage) => void) | undefined) => http.ClientRequest;
    request: (url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: ((res: http.IncomingMessage) => void) | undefined) => http.ClientRequest;
};
export interface SecureContextOptionsPatch {
    _vscodeAdditionalCaCerts?: (string | Buffer)[];
    _vscodeTestReplaceCaCerts?: boolean;
}
export declare function createNetPatch(params: ProxyAgentParams, originals: typeof net): {
    connect: typeof net.connect;
};
export declare function createTlsPatch(params: ProxyAgentParams, originals: typeof tls): {
    connect: typeof tls.connect;
    createSecureContext: typeof tls.createSecureContext;
};
export declare function createFetchPatch(params: ProxyAgentParams, originalFetch: typeof globalThis.fetch, resolveProxyURL: (url: string) => Promise<string | undefined>): (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
export declare function patchUndici(originalUndici: typeof undici): void;
export declare function getOrLoadAdditionalCertificates(params: ProxyAgentParams): Promise<string[]>;
export interface CertificateParams {
    log: Log;
}
export declare function loadSystemCertificates(params: CertificateParams): Promise<string[]>;
export declare function resetCaches(): void;
export declare function toLogString(args: any[]): string;
/**
 * Certificates for testing. These are not automatically used, but can be added in
 * ProxyAgentParams#loadAdditionalCertificates(). This just provides a shared array
 * between production code and tests.
 */
export declare const testCertificates: string[];
export {};
