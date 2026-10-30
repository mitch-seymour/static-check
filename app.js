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
  const lib = window.honeypot;
  if (!lib || !lib.staticConfig) {
    status.className = 'bad';
    status.textContent = 'Script did not run (blocked by the integrity check or failed to load).';
    return;
  }
  status.className = 'ok';
  status.textContent = 'Script loaded and passed the integrity check. Waiting for the decision…';
  const started = performance.now();
  await lib.ready;
  const g = lib.geofenceResults || {};
  const blocked = Boolean(g.redirectUrl) && g.autoRedirect !== false;
  status.textContent = blocked
    ? g.challenge && g.challenge.allow
      ? 'Restricted location: the location check dialog is shown.'
      : 'Restricted location: redirecting…'
    : 'Allowed: no restriction for this connection.';
  status.className = blocked ? 'warn' : 'ok';
  table.append(
    row('decision time', `${Math.round(performance.now() - started)} ms after load`),
    row('redirect', g.redirectUrl ? `${g.redirectUrl} (auto: ${g.autoRedirect !== false})` : 'none'),
    row('challenge offered', g.challenge && g.challenge.allow ? 'yes' : 'no'),
    row('rescreening', g.rescreenEnabled ? `every ${g.rescreenFrequencySeconds}s` : 'off'),
    row('reference', g.ref || '-'),
    row('library', lib.version)
  );
}

show();
