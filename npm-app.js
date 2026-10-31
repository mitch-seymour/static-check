// The npm package page: the package's ESM build is served from this site like
// any bundled app code. Nothing is loaded from the Honeypot worker except the
// encrypted pings.
import honeypot from './npm/core-embedded.mjs';
import settings from './npm/settings.js';

const violations = [];
document.addEventListener('securitypolicyviolation', (e) => {
  violations.push(`${e.effectiveDirective} blocked ${e.blockedURI || '(inline)'}`);
  document.getElementById('csp').textContent = violations.join('\n');
});

function row(label, value) {
  const tr = document.createElement('tr');
  const th = document.createElement('th');
  const td = document.createElement('td');
  th.textContent = label;
  td.textContent = value;
  tr.append(th, td);
  return tr;
}

async function show() {
  const status = document.getElementById('status');
  const table = document.getElementById('result');
  const started = performance.now();
  try {
    honeypot.start(settings);
  } catch (error) {
    status.className = 'bad';
    status.textContent = `start() refused the settings: ${error.message}`;
    return;
  }
  status.className = 'ok';
  status.textContent = 'Package started. Waiting for the decision…';
  await honeypot.ready;
  const g = honeypot.geofenceResults || {};
  const blocked = Boolean(g.redirectUrl) && g.autoRedirect !== false;
  status.textContent = blocked
    ? g.challenge && g.challenge.allow
      ? 'Restricted location: the location check dialog is shown.'
      : 'Restricted location: redirecting…'
    : 'Allowed: no restriction for this connection.';
  status.className = blocked ? 'warn' : 'ok';
  table.append(
    row('decision time', `${Math.round(performance.now() - started)} ms after start()`),
    row('redirect', g.redirectUrl ? `${g.redirectUrl} (auto: ${g.autoRedirect !== false})` : 'none'),
    row('challenge offered', g.challenge && g.challenge.allow ? 'yes' : 'no'),
    row('rescreening', g.rescreenEnabled ? `every ${g.rescreenFrequencySeconds}s` : 'off'),
    row('reference', g.ref || '-'),
    row('library', `@honeypot-run/core-embedded ${honeypot.version}`)
  );
}

show();
