/**
 * Conservative path traversal detection.
 *
 * The scanner never requests /etc/passwd, boot.ini, application config or any
 * other sensitive file. Instead it answers two safe questions:
 *
 *   1. Does the parameter behave like a filesystem path?
 *      Probe `zzqx/../<original>` next to the control `zzqx/<original>`.
 *      If the control breaks the page but the `..` version renders exactly the
 *      baseline, the server resolved the traversal sequence itself.
 *
 *   2. Does a traversal sequence reach the filesystem?
 *      Probe a random, certainly-nonexistent name behind `../`. A filesystem
 *      error - especially one disclosing an absolute path - shows the value is
 *      concatenated into a real path.
 *
 * Both probes are read-only and target names that do not exist.
 */
import { SEVERITY, CONFIDENCE } from '../config/index.js';
import { similarity, excerpt } from '../utils/text.js';
import { canaryToken } from '../utils/ids.js';
import { FILE_ERRORS, PATH_DISCLOSURE, matchSignatures, matchAny } from './signatures.js';
import { sendProbe } from './injectionPoints.js';

const RECOMMENDATION =
  'Never concatenate user input into a filesystem path. Resolve the requested path to its canonical form ' +
  '(realpath) and verify it is still inside an allowlisted base directory before opening it. Better still, map ' +
  'user input to an identifier and look the real filename up server-side, and run the application with an account ' +
  'that cannot read anything outside its own content directory.';

/** Parameter names that commonly address a file or a path. */
const PATH_PARAMETER = /^(file|filename|file_name|filepath|file_path|path|dir|directory|folder|doc|document|page|template|tpl|view|include|inc|load|read|download|attachment|resource|asset|img|image|photo|media|src|url_path|report|export|log|name)$/i;

/** Values that look like a file reference. */
const PATH_LIKE_VALUE = /^[\w .\-]+\.[a-z0-9]{2,5}$|^[\w.\-]+\/[\w./\-]+$/i;

const looksPathRelated = (point) =>
  PATH_PARAMETER.test(point.parameter) || PATH_LIKE_VALUE.test(String(point.baseValue || ''));

/**
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @param {object} point
 */
export async function checkPathTraversal(ctx, point) {
  if (!looksPathRelated(point)) return;

  const base = String(point.baseValue || '').trim();
  const marker = canaryToken('pt');

  // --- probe 2 first: it works even when there is no usable base value ------
  const missingName = `../${marker}`;
  const missing = await sendProbe(ctx, point, missingName, 'traversal-error');
  if (!missing.ok) return;

  const fileError = matchSignatures(missing.body || '', FILE_ERRORS, 'platform');
  if (fileError.matched) {
    const disclosedPath = matchAny(missing.body, PATH_DISCLOSURE);
    const index = missing.body.indexOf(fileError.match);

    ctx.addFinding({
      type: 'Potential Path Traversal',
      severity: SEVERITY.HIGH,
      confidence: disclosedPath ? CONFIDENCE.MEDIUM : CONFIDENCE.LOW,
      url: missing.url,
      parameter: point.parameter,
      method: point.method,
      description:
        `"${point.parameter}" appears to be used as a filesystem path. Sending the non-existent relative path ` +
        `"${missingName}" produced a ${fileError.label || 'filesystem'} error` +
        (disclosedPath
          ? `, and the error disclosed the absolute server path "${disclosedPath}". The traversal sequence was ` +
            `carried into a real path lookup rather than being rejected.`
          : `, which shows the value reaches a file operation. The error did not disclose a path, so the extent of ` +
            `the traversal is unconfirmed.`) +
        ' The probe targeted a random name that cannot exist; no sensitive file was requested or retrieved.',
      evidence:
        `Probe value: ${missingName}\n` +
        `HTTP ${missing.status}\n` +
        `Matched ${fileError.label || 'filesystem'} error: ${fileError.match}` +
        (disclosedPath ? `\nDisclosed path: ${disclosedPath}` : '') +
        (index >= 0 ? `\nSnippet: ${excerpt(missing.body, index, 120)}` : ''),
      recommendation: RECOMMENDATION,
      references: ['https://owasp.org/www-community/attacks/Path_Traversal', 'CWE-22'],
    });
    return;
  }

  // --- probe 1: does the server itself collapse "dir/.." ? ------------------
  if (!base || base.includes('..') || base.startsWith('/')) return;

  const baseline = await sendProbe(ctx, point, base, 'traversal-baseline');
  if (!baseline.ok || !baseline.body || baseline.status >= 400) return;

  const baselineRepeat = await sendProbe(ctx, point, base, 'traversal-baseline');
  if (!baselineRepeat.ok) return;
  const noiseFloor = similarity(baseline.body, baselineRepeat.body);
  if (noiseFloor < 0.9) return; // page too dynamic to compare

  const control = await sendProbe(ctx, point, `${marker}/${base}`, 'traversal-control');
  if (!control.ok) return;
  const controlSimilarity = similarity(baseline.body, control.body);
  const controlBreaksPage = control.status !== baseline.status || controlSimilarity < noiseFloor - 0.2;
  if (!controlBreaksPage) return; // a bogus directory changes nothing - not a real path lookup

  const traversal = await sendProbe(ctx, point, `${marker}/../${base}`, 'traversal-probe');
  if (!traversal.ok) return;
  const traversalSimilarity = similarity(baseline.body, traversal.body);
  const traversalMatchesBaseline =
    traversal.status === baseline.status && traversalSimilarity >= noiseFloor - 0.05;

  if (traversalMatchesBaseline) {
    ctx.addFinding({
      type: 'Potential Path Traversal',
      severity: SEVERITY.HIGH,
      confidence: CONFIDENCE.MEDIUM,
      url: traversal.url,
      parameter: point.parameter,
      method: point.method,
      description:
        `"${point.parameter}" is resolved as a filesystem path and "../" sequences inside it are honoured rather ` +
        `than rejected. Prefixing a non-existent directory ("${marker}/${base}") broke the response, but adding ` +
        `the traversal that cancels it out ("${marker}/../${base}") returned exactly the baseline page - so the ` +
        `server walked back out of that directory. A parameter that can climb one level can usually climb several. ` +
        `Only the original, already-public resource was requested; the scanner did not attempt to reach any file ` +
        `outside the web root.`,
      evidence:
        `Baseline stability: ${noiseFloor.toFixed(3)}\n` +
        `Baseline (${base}): HTTP ${baseline.status}\n` +
        `Bogus prefix (${marker}/${base}): HTTP ${control.status}, similarity ${controlSimilarity.toFixed(3)}\n` +
        `Self-cancelling traversal (${marker}/../${base}): HTTP ${traversal.status}, similarity ${traversalSimilarity.toFixed(3)}`,
      recommendation: RECOMMENDATION,
      references: ['https://owasp.org/www-community/attacks/Path_Traversal', 'CWE-22'],
    });
  }
}
