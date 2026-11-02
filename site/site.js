'use strict';

// Progressive enhancement: the first candidate and every other section are HTML.
const evidenceLoad = fetch('evidence/triage-example.json')
  .then(response => {
    if (!response.ok) throw new Error('Evidence unavailable');
    return response.json();
  })
  .then(record => record.candidates)
  .catch(() => null);

const label = value => value.charAt(0).toUpperCase() + value.slice(1).replaceAll('-', ' ');
const methodName = signature => {
  const match = signature.match(/^<([^:]+): .+ ([^ (]+)\(/);
  return match ? `${match[1]}.${match[2]}` : signature;
};
const findings = {
  1: ['A new route through target code.', 'No catalogued family matched. This is a deliberate test fixture; the label is a review signal, not a new vulnerability claim.'],
  0: ['A second deserialization boundary.', 'The fixture reaches an ObjectInputStream constructor. The candidate has no catalogued family match; semantic reachability and feasibility have not been analyzed.'],
  2396: ['A known family stays in view.', 'The catalog identifies the JRMP client family. This candidate reaches an outbound request; a known-family match does not establish that the complete route is feasible.'],
  495: ['The runtime changes the route.', 'AnnotationInvocationHandler.readObject rebuilds memberValues as a fresh LinkedHashMap (JDK 8u71+), so invoke() no longer dispatches to an attacker-chosen map.']
};
let latestSelection = 1;
for (const button of document.querySelectorAll('.chain-row')) {
  button.addEventListener('click', async () => {
    const id = Number(button.dataset.chain);
    latestSelection = id;
    const candidates = await evidenceLoad;
    if (latestSelection !== id) return;
    const candidate = candidates?.find(item => item.chain_id === id);
    if (!candidate) {
      document.getElementById('evidence-finding').textContent = 'The recorded evidence could not be loaded. Reload the page or use “Inspect the recorded evidence” above to read the source file.';
      return;
    }
    for (const row of document.querySelectorAll('.chain-row')) {
      const selected = row === button;
      row.classList.toggle('selected', selected);
      row.setAttribute('aria-pressed', String(selected));
    }
    const set = (name, text) => { document.getElementById(`evidence-${name}`).textContent = text; };
    set('rank', `Review #${candidate.rank + 1}`);
    set('effect', label(candidate.effect));
    set('title', findings[id][0]);
    set('entry', methodName(candidate.entry));
    set('sink', methodName(candidate.sink));
    const gap = document.getElementById('evidence-gap');
    gap.hidden = candidate.edge_count === 1;
    gap.textContent = `${candidate.edge_count - 1} intermediate calls omitted; expand the trace below`;
    set('novelty', label(candidate.novelty));
    set('mitigation', candidate.blocked ? 'Blocked' : candidate.constrained ? 'Constrained' : 'None flagged');
    set('finding', findings[id][1]);
    set('trace', candidate.trace);
    document.getElementById('candidate-status').textContent = `Review #${candidate.rank + 1} selected. ${label(candidate.novelty)}. ${candidate.blocked ? 'Blocked by a runtime mitigation.' : 'No mitigation flagged.'} Feasibility not analyzed.`;
  });
}

for (const button of document.querySelectorAll('.copy')) {
  let reset;
  button.addEventListener('click', async () => {
    const code = button.nextElementSibling;
    const feedback = document.getElementById('copy-feedback');
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = 'Copied';
      feedback.textContent = 'Command copied to clipboard.';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = 'Selected';
      feedback.textContent = 'Clipboard unavailable. Command selected; use your browser’s copy command.';
    }
    reset = setTimeout(() => { button.textContent = 'Copy'; }, 2000);
  });
}
