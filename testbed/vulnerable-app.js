/**
 * ============================================================================
 *  INTENTIONALLY VULNERABLE TEST APPLICATION - LOCALHOST ONLY
 * ============================================================================
 *
 * A tiny target for exercising the scanner end to end. Every flaw in here is
 * deliberate: unencoded reflection, string-concatenated SQL, a path parameter
 * joined straight onto a directory, and no security headers.
 *
 * It binds to 127.0.0.1 only, has no real database and no real filesystem
 * access - the "database" and "files" are in-memory objects, so nothing here
 * can be used against anything. NEVER deploy this or expose it to a network.
 *
 * Run:   node testbed/vulnerable-app.js
 * Then:  scan http://127.0.0.1:4500 with ALLOW_PRIVATE_TARGETS=true set on the
 *        scanner backend.
 */
import http from 'node:http';

const PORT = Number(process.env.PORT || 4500);
const HOST = '127.0.0.1';

const PRODUCTS = [
  { id: 1, name: 'Climbing rope', price: 89 },
  { id: 2, name: 'Belay device', price: 35 },
  { id: 3, name: 'Chalk bag', price: 18 },
];

const FILES = {
  'content/report.txt': 'Quarterly report: revenue up 4%.\n',
  'content/notes.txt': 'Remember to renew the certificate.\n',
};

const page = (title, body) => `<!doctype html>
<html><head><title>${title}</title></head>
<body><header><a href="/">Home</a></header>${body}</body></html>`;

const send = (res, status, body, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
};

/** Resolve a path the naive way: join onto a base directory, collapse "..". */
function naiveResolve(value) {
  const stack = [];
  for (const segment of `content/${value}`.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') stack.pop();
    else stack.push(segment);
  }
  return stack.join('/');
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const params = url.searchParams;

  switch (url.pathname) {
    case '/robots.txt':
      return send(res, 200, 'User-agent: *\nDisallow: /admin\n', { 'Content-Type': 'text/plain' });

    case '/':
      return send(
        res,
        200,
        page(
          'Test shop',
          `<h1>Test shop</h1>
           <nav>
             <a href="/search?q=rope">Search</a>
             <a href="/product?id=1">Product 1</a>
             <a href="/product?id=2">Product 2</a>
             <a href="/catalogue?category=gear">Catalogue</a>
             <a href="/download?file=report.txt">Download report</a>
             <a href="/view?path=notes.txt">View notes</a>
             <a href="/about">About</a>
             <a href="/admin">Admin</a>
           </nav>
           <form action="/search" method="GET">
             <input type="text" name="q" placeholder="Search"><button type="submit">Go</button>
           </form>
           <form action="/subscribe" method="POST">
             <input type="email" name="email"><button type="submit">Subscribe</button>
           </form>
           <script>fetch("/api/v1/products?limit=10");</script>
           <script src="/static/app.js"></script>`,
        ),
        { 'Set-Cookie': 'sessionid=demo-session-value; Path=/' },
      );

    case '/about':
      return send(res, 200, page('About', '<h1>About</h1><p>A deliberately vulnerable demo app.</p>'));

    case '/admin':
      return send(res, 200, page('Admin', '<h1>Admin</h1><p>Disallowed in robots.txt.</p>'));

    case '/static/app.js':
      return send(
        res,
        200,
        'axios.get("/api/v1/orders?page=1");\nconst users = "/api/v1/users";\n',
        { 'Content-Type': 'application/javascript' },
      );

    // Reflected XSS: the query value is written into HTML with no encoding.
    case '/search': {
      const q = params.get('q') ?? '';
      return send(res, 200, page('Search', `<h1>Search</h1><p>You searched for ${q}</p>`));
    }

    // Error-based SQL injection: unbalanced quotes surface a "database" error.
    case '/product': {
      const id = params.get('id') ?? '';
      if ((id.split("'").length - 1) % 2 === 1) {
        return send(
          res,
          500,
          page(
            'Error',
            `<h1>Database error</h1><pre>You have an error in your SQL syntax; check the manual that ` +
              `corresponds to your MySQL server version for the right syntax to use near '${id}' at line 1</pre>`,
          ),
        );
      }
      const product = PRODUCTS.find((entry) => entry.id === Number.parseInt(id, 10)) || PRODUCTS[0];
      return send(res, 200, page('Product', `<h1>${product.name}</h1><p>Price: ${product.price}</p>`));
    }

    // Boolean-based SQL injection: an always-false condition returns no rows.
    case '/catalogue': {
      const category = params.get('category') ?? '';
      const alwaysFalse = /\b1\s*=\s*2\b|'1'\s*=\s*'2/.test(category);
      return send(
        res,
        200,
        page(
          'Catalogue',
          alwaysFalse
            ? '<h1>Catalogue</h1><p>No items matched.</p>'
            : `<h1>Catalogue</h1><ul>${PRODUCTS.map((p) => `<li>${p.name}</li>`).join('')}</ul>`,
        ),
      );
    }

    // Path traversal: the parameter is joined onto a directory and the error
    // leaks the resolved path.
    case '/download': {
      const file = params.get('file') ?? '';
      const resolved = naiveResolve(file);
      if (FILES[resolved]) {
        return send(res, 200, FILES[resolved], { 'Content-Type': 'text/plain' });
      }
      return send(
        res,
        500,
        page('Error', `<pre>Error: ENOENT: no such file or directory, open '/srv/testbed/${resolved}'</pre>`),
      );
    }

    // Path traversal with no error message - only a behavioural difference.
    case '/view': {
      const target = params.get('path') ?? '';
      const resolved = naiveResolve(target);
      if (FILES[resolved]) {
        return send(res, 200, page('Document', `<h1>Document</h1><p>${FILES[resolved]}</p>`));
      }
      return send(res, 404, page('Not found', '<h1>404</h1><p>Document unavailable.</p>'));
    }

    case '/subscribe':
      return send(res, 200, page('Subscribed', '<p>Thanks for subscribing.</p>'));

    default:
      if (url.pathname.startsWith('/api/')) {
        return send(res, 200, '{"items":[]}', { 'Content-Type': 'application/json' });
      }
      return send(res, 404, page('Not found', '<h1>404</h1>'));
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(
    `Intentionally vulnerable test app on http://${HOST}:${PORT} - localhost only, never expose this.\n`,
  );
});
