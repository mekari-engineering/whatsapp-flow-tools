const http = require('http');
const { processFlowRequest } = require('./hospital booking/booking');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function collectBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';

    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1024 * 1024) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error('Invalid JSON payload'));
      }
    });

    req.on('error', (error) => {
      reject(error);
    });
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    sendJson(res, 200, { status: 'ok' });
    return;
  }

  if (req.method === 'POST' && req.url === '/webhook') {
    try {
      const body = await collectBody(req);
      const result = await processFlowRequest(body);

      const statusCode = Number(result?.code) || 200;
      sendJson(res, statusCode, result);
    } catch (error) {
      console.error('Request handling error:', error);
      sendJson(res, 400, {
        code: 400,
        message: error.message || 'Bad Request'
      });
    }
    return;
  }

  sendJson(res, 404, {
    code: 404,
    message: 'Not Found'
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Server listening on http://${HOST}:${PORT}`);
  console.log('POST /webhook to process WhatsApp Flow payloads');
});
