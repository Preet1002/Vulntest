/**
 * Response fingerprints shared by the detection modules.
 *
 * Every entry is a *read-only* indicator: something the application leaked in
 * its own error output. Matching these is how the scanner gathers evidence
 * without sending destructive input.
 */

/** Database error messages, grouped by engine. */
export const DATABASE_ERRORS = [
  { engine: 'MySQL', pattern: /You have an error in your SQL syntax/i },
  { engine: 'MySQL', pattern: /warning: \s*mysqli?_/i },
  { engine: 'MySQL', pattern: /valid MySQL result resource/i },
  { engine: 'MySQL', pattern: /com\.mysql\.jdbc\.exceptions/i },
  { engine: 'MySQL', pattern: /MySqlException/i },
  { engine: 'MySQL', pattern: /check the manual that corresponds to your (?:MySQL|MariaDB) server version/i },
  { engine: 'PostgreSQL', pattern: /PostgreSQL query failed/i },
  { engine: 'PostgreSQL', pattern: /pg_(?:query|exec|connect)\(\)/i },
  { engine: 'PostgreSQL', pattern: /org\.postgresql\.util\.PSQLException/i },
  { engine: 'PostgreSQL', pattern: /unterminated quoted string at or near/i },
  { engine: 'PostgreSQL', pattern: /syntax error at or near/i },
  { engine: 'Microsoft SQL Server', pattern: /Microsoft OLE DB Provider for (?:ODBC|SQL Server)/i },
  { engine: 'Microsoft SQL Server', pattern: /Unclosed quotation mark after the character string/i },
  { engine: 'Microsoft SQL Server', pattern: /Incorrect syntax near/i },
  { engine: 'Microsoft SQL Server', pattern: /System\.Data\.SqlClient\.SqlException/i },
  { engine: 'Oracle', pattern: /\bORA-\d{5}\b/ },
  { engine: 'Oracle', pattern: /quoted string not properly terminated/i },
  { engine: 'Oracle', pattern: /Oracle.*?(?:Driver|Exception)/i },
  { engine: 'SQLite', pattern: /SQLite(?:3)?::(?:query|exec)/i },
  { engine: 'SQLite', pattern: /sqlite3?\.OperationalError/i },
  { engine: 'SQLite', pattern: /unrecognized token:/i },
  { engine: 'SQLite', pattern: /SQLite\/JDBCDriver/i },
  { engine: 'IBM DB2', pattern: /(?:DB2 SQL error|SQLCODE=-\d+)/i },
  { engine: 'Sybase', pattern: /Sybase message:/i },
  { engine: 'Generic SQL', pattern: /SQLSTATE\[[0-9A-Z]{5}\]/ },
  { engine: 'Generic SQL', pattern: /\bSQLException\b/ },
  { engine: 'Generic SQL', pattern: /Dynamic SQL Error/i },
  { engine: 'ORM', pattern: /(?:Sequelize|Knex|TypeORM|Doctrine|Hibernate)[^\n]{0,40}(?:Error|Exception)/i },
];

/** Filesystem access errors - evidence for path traversal handling. */
export const FILE_ERRORS = [
  { platform: 'PHP', pattern: /failed to open stream: No such file or directory/i },
  { platform: 'PHP', pattern: /(?:include|require)(?:_once)?\(\)[^\n]{0,80}Failed opening/i },
  { platform: 'PHP', pattern: /open_basedir restriction in effect/i },
  { platform: 'Node.js', pattern: /ENOENT[,:]?\s*no such file or directory/i },
  { platform: 'Node.js', pattern: /Error: ENOENT/i },
  { platform: 'Java', pattern: /java\.io\.FileNotFoundException/i },
  { platform: 'Java', pattern: /java\.nio\.file\.(?:NoSuchFileException|InvalidPathException)/i },
  { platform: '.NET', pattern: /System\.IO\.(?:FileNotFound|DirectoryNotFound|Path.{0,10})Exception/i },
  { platform: '.NET', pattern: /Could not find (?:file|a part of the path)/i },
  { platform: 'Python', pattern: /FileNotFoundError:\s*\[Errno 2\]/i },
  { platform: 'Python', pattern: /IsADirectoryError|NotADirectoryError/i },
  { platform: 'Ruby', pattern: /Errno::ENOENT/i },
  { platform: 'Generic', pattern: /No such file or directory/i },
];

/** Absolute filesystem paths leaking from error output. */
export const PATH_DISCLOSURE = [
  /(?:\/(?:var|usr|home|opt|srv|etc|tmp|www|app|data|mnt)\/[\w.\-]+(?:\/[\w.\-]+){1,8})/,
  /[A-Za-z]:\\(?:inetpub|windows|users|xampp|wamp|www|apps?|data)\\[\w\-. \\]{3,80}/i,
];

/** Framework stack traces / debug output. */
export const STACK_TRACES = [
  { platform: 'PHP', pattern: /(?:Fatal error|Parse error|Warning):[^\n]{0,120} in [^\n]{0,160} on line \d+/i },
  { platform: 'Python', pattern: /Traceback \(most recent call last\)/ },
  { platform: 'Java', pattern: /\bat [\w$.]+\([\w$]+\.java:\d+\)/ },
  { platform: '.NET', pattern: /\[\w*Exception:[^\]]{0,120}\]/ },
  { platform: '.NET', pattern: /Server Error in '.*' Application/i },
  { platform: 'Node.js', pattern: /\bat [\w$.<> ]+\([^\n]{0,160}:\d+:\d+\)/ },
  { platform: 'Rails', pattern: /(?:ActionController|ActiveRecord)::\w+Error/ },
  { platform: 'Django', pattern: /(?:DjangoDebug|You're seeing this error because you have DEBUG = True)/i },
];

/** Server generated directory listings. */
export const DIRECTORY_LISTING = [
  /<title>\s*Index of \//i,
  /<h1>\s*Index of \//i,
  /Directory listing for \//i,
  /\[To Parent Directory\]/i,
];

/**
 * Run a signature list against a body.
 * @returns {{matched: boolean, label: string|null, match: string|null}}
 */
export function matchSignatures(body, signatures, labelKey = 'engine') {
  if (!body) return { matched: false, label: null, match: null };
  const text = String(body).slice(0, 300_000);

  for (const signature of signatures) {
    const pattern = signature.pattern || signature;
    const found = text.match(pattern);
    if (found) {
      return {
        matched: true,
        label: signature[labelKey] || null,
        match: found[0].slice(0, 200),
      };
    }
  }
  return { matched: false, label: null, match: null };
}

export const matchAny = (body, patterns) => {
  if (!body) return null;
  const text = String(body).slice(0, 300_000);
  for (const pattern of patterns) {
    const found = text.match(pattern);
    if (found) return found[0].slice(0, 200);
  }
  return null;
};
