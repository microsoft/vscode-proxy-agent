/// <reference types="node" />
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
import { ProxyResolveType } from './agent';
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
export interface ProxyAuthorizationInfo {
    scheme: 'basic';
    host: string;
    port: number;
    realm: string;
    isProxy: true;
    attempt: number;
}
export interface ProxyAuthorizationCredentials {
    username: string;
    password: string;
}
export interface ProxyAuthorizationLookupParams {
    log: Log;
    lookupKerberosAuthorization?(proxyURL: string): Promise<string | undefined>;
    lookupAuthorization?(authInfo: ProxyAuthorizationInfo): Promise<ProxyAuthorizationCredentials | undefined>;
    onDidRequestAuthentication?(authenticationChallenges: string[]): void;
}
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
    isWebSocketPatchEnabled: () => boolean;
    addCertificatesV1: () => boolean;
    addCertificatesV2: () => boolean;
    loadSystemCertificatesFromNode: () => boolean | undefined;
    loadAdditionalCertificates(): Promise<string[]>;
    lookupProxyAuthorization?: LookupProxyAuthorization;
    log: Log;
    getLogLevel(): LogLevel;
    proxyResolveTelemetry(event: ProxyResolveEvent): void;
    isUseHostProxyEnabled: () => boolean;
    getNetworkInterfaceCheckInterval?: () => number;
    env: NodeJS.ProcessEnv;
}
export declare function createProxyAuthorizationLookup(params: ProxyAuthorizationLookupParams): LookupProxyAuthorization;
export type { ProxyResolveType } from './agent';
/**
 * Which configuration determined the resolved proxy. Mirrors the resolution
 * order in `useProxySettings`:
 * - `localhost`: the target is a loopback host (always direct).
 * - `noProxyConfig`: excluded by the `http.noProxy` setting.
 * - `noProxyEnv`: excluded by the `no_proxy`/`NO_PROXY` environment variable.
 * - `setting`: the `http.proxy` setting (via `getProxyURL`).
 * - `env`: the `http(s)_proxy` environment variable.
 * - `remote`: host proxy resolution is disabled (`isUseHostProxyEnabled` is false), e.g. in remote scenarios.
 * - `system_cached`: served from the in-memory cache of a previous system resolution.
 * - `system`: resolved via the operating system / PAC (`resolveProxy`).
 * - `fallback`: system resolution failed and a cached proxy was used as fallback.
 */
export type ProxyResolveSource = 'localhost' | 'noProxyConfig' | 'noProxyEnv' | 'setting' | 'env' | 'remote' | 'system_cached' | 'system' | 'fallback';
/**
 * Structured result of {@link createProxyResolver}'s `resolveProxyByURL`.
 */
export interface ResolvedProxyInfo {
    /** The resolved proxy URL, or `undefined` for a direct connection. */
    url: string | undefined;
    /** The resolved proxy type. */
    type: ProxyResolveType;
    /** Which configuration determined the result. */
    source: ProxyResolveSource;
}
export declare function createProxyResolver(params: ProxyAgentParams): {
    resolveProxyWithRequest: (flags: {
        useProxySettings: boolean;
        addCertificatesV1: boolean;
        testCertificates?: (string | Buffer)[] | undefined;
    }, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) => void;
    resolveProxyURL: (url: string) => Promise<string | undefined>;
    resolveProxyByURL: (url: string) => Promise<ResolvedProxyInfo>;
};
export type ProxySupportSetting = 'override' | 'fallback' | 'on' | 'off';
export type ResolveProxyWithRequest = (flags: {
    useProxySettings: boolean;
    addCertificatesV1: boolean;
    testCertificates?: (string | Buffer)[];
}, req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy?: string) => void) => void;
export declare function createHttpPatch(params: ProxyAgentParams, originals: typeof http | typeof https, resolveProxy: ResolveProxyWithRequest): {
    get: (url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: ((res: http.IncomingMessage) => void) | undefined) => http.ClientRequest;
    request: (url?: string | nodeurl.URL | null, options?: http.RequestOptions | null, callback?: ((res: http.IncomingMessage) => void) | undefined) => http.ClientRequest;
};
export interface SecureContextOptionsPatch {
    _vscodeAdditionalCaCerts?: (string | Buffer)[];
    _vscodeTestReplaceCaCerts?: boolean;
    testCertificates?: (string | Buffer)[];
}
export interface CreateFetchPatchOptions {
    interceptors?: readonly undici.Dispatcher.DispatcherComposeInterceptor[];
}
export declare function createNetPatch(params: ProxyAgentParams, originals: typeof net): {
    connect: typeof net.connect;
};
export declare function createTlsPatch(params: ProxyAgentParams, originals: typeof tls): {
    connect: typeof tls.connect;
    createSecureContext: typeof tls.createSecureContext;
};
export declare function createFetchPatch(params: ProxyAgentParams, originalFetch: typeof globalThis.fetch, resolveProxyURL: (url: string) => Promise<string | undefined>, options?: CreateFetchPatchOptions): (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
export declare function createWebSocketPatch(params: ProxyAgentParams, originalWebSocket: typeof globalThis.WebSocket, resolveProxyURL: (url: string) => Promise<string | undefined>): {
    new (url: string | URL, protocols?: string | string[] | undefined): WebSocket;
    prototype: WebSocket;
    readonly CONNECTING: 0;
    readonly OPEN: 1;
    readonly CLOSING: 2;
    readonly CLOSED: 3;
};
/** @internal Exported for testing */
export declare function setProxyAuthorizationHeader(options: undici.Dispatcher.DispatchOptions, proxyAuthorization: string): void;
export declare function patchUndici(originalUndici: typeof undici): void;
export declare function getOrLoadAdditionalCertificates(params: ProxyAgentParams): Promise<string[]>;
export interface CertificateParams {
    loadSystemCertificatesFromNode: () => boolean | undefined;
    log: Log;
}
export declare function loadSystemCertificates(params: CertificateParams): Promise<string[]>;
export declare function resetCaches(): void;
export declare function toLogString(args: any[]): string;
