const https = require('https');
const fs = require('fs');
const { WebSocketServer } = require('ws');

const server = https.createServer({
	cert: fs.readFileSync('/app/certs/ssl_cert.pem'),
	key: fs.readFileSync('/app/certs/ssl_key.pem'),
}, (req, res) => {
	res.writeHead(200);
	res.end('OK');
});

const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
	ws.on('message', (data) => {
		ws.send(data);
	});
});

server.listen(443, () => {
	console.log('WSS echo server listening on port 443');
});
