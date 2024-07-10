const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
	console.log('Sending pac file...');
	const filePath = path.join(__dirname, 'test.pac');
	const stat = fs.statSync(filePath);

	res.writeHead(200, {
		'Content-Type': 'application/x-ns-proxy-autoconfig',
		'Content-Length': stat.size
	});

	const readStream = fs.createReadStream(filePath);
	readStream.pipe(res);
});

server.listen(3333, () => {
	console.log('Server is running on port 3333');
});