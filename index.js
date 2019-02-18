
/**
 * Module exports.
 */

module.exports = exports = { ProxyAgent };

/**
 * Module dependencies.
 */

var http = require('http');
var parse = require('url').parse;
var format = require('url').format;
var HttpProxyAgent = require('http-proxy-agent');
var HttpsProxyAgent = require('https-proxy-agent');
var SocksProxyAgent = require('socks-proxy-agent');
var debug = require('debug')('vscode-proxy-agent');

/**
 * The `ProxyAgent` class.
 *
 * options : {
 *   resolveProxy(req, opts, url, callback)
 * }
 * 
 * See https://github.com/atom/electron/blob/master/docs/api/session.md#sesresolveproxyurl-callback
 *
 * @api public
 */

function ProxyAgent(session) {
  if (!(this instanceof ProxyAgent)) return new ProxyAgent(session);

  this.session = session;
  this.addRequest = addRequest;
  this.defaultPort = session.defaultPort;
}

/**
 * Called when the node-core HTTP client library is creating a new HTTP request.
 *
 * @api public
 */

function addRequest (req, opts) {
  var url;
  var self = this;

  // calculate the `url` parameter
  var defaultAgent = opts._defaultAgent || http.globalAgent;
  var path = req.path;
  var firstQuestion = path.indexOf('?');
  var search;
  if (-1 != firstQuestion) {
    search = path.substring(firstQuestion);
    path = path.substring(0, firstQuestion);
  }
  url = format(Object.assign({}, opts, {
    protocol: defaultAgent.protocol,
    pathname: path,
    search: search,

    // need to use `hostname` instead of `host` otherwise `port` is ignored
    hostname: opts.host,
    host: null,

    // set `port` to null when it is the protocol default port (80 / 443)
    port: defaultAgent.defaultPort == opts.port ? null : opts.port
  }));

  debug('url: %o', url);
  self.session.resolveProxy(req, opts, url, onproxy);

  // `resolveProxy()` callback function
  function onproxy (proxy) {

    // default to "DIRECT" if a falsey value was returned (or nothing)
    if (!proxy) proxy = 'DIRECT';

    var proxies = String(proxy).trim().split(/\s*;\s*/g).filter(Boolean);

    // XXX: right now, only the first proxy specified will be used
    var first = proxies[0];
    debug('using proxy: %o', first);

    var agent;
    var parts = first.split(/\s+/);
    var type = parts[0];

    if ('DIRECT' == type) {
      // direct connection to the destination endpoint
      agent = this.session.originalAgent || defaultAgent;
    } else if ('SOCKS' == type) {
      // use a SOCKS proxy
      agent = new SocksProxyAgent('socks://' + parts[1]);
    } else if ('PROXY' == type || 'HTTPS' == type) {
      // use an HTTP or HTTPS proxy
      // http://dev.chromium.org/developers/design-documents/secure-web-proxy
      var proxyURL = ('HTTPS' === type ? 'https' : 'http') + '://' + parts[1];
      var proxy = parse(proxyURL);
      if (defaultAgent.protocol === 'https:') {
        agent = new HttpsProxyAgent(proxy);
      } else {
        agent = new HttpProxyAgent(proxy);
      }
    } else {
      // direct connection to the destination endpoint
      agent = this.session.originalAgent || defaultAgent;
    }
    agent.addRequest(req, opts);
  }
}
