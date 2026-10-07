// Deterministic DOM contract test; does not launch a browser or access networking.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const events = {};
function element(severity, filter) {
    return {
        hidden: false, open: false, parentElement: null, handlers: {},
        getAttribute(name) { return name === 'data-severity' ? severity : filter; },
        classList: { toggle() {} },
        addEventListener(name, fn) { this.handlers[name] = fn; },
        matches(selector) { return selector === '[data-severity]' ? !!severity : selector === 'details' && this.isDetails; },
        querySelector() { return this.disclosure || null; },
        scrollIntoView() { this.scrolled = true; }
    };
}
const high = element('high');
const low = element('low');
const highButton = element(null, 'high');
const allButton = element(null, 'all');
const closed = element(); closed.isDetails = true;
const opened = element(); opened.isDetails = true; opened.open = true;
const coverage = element(); coverage.disclosure = closed;
const child = element(); child.parentElement = closed;
const link = element();
const targets = { coverage, finding: low, child };
const selectors = {
    '.filter': [highButton, allButton],
    '[data-severity]': [high, low],
    '.tile[data-filter]': [],
    'details': [closed, opened],
    'a[href^="#"]': [link]
};
const window = {
    location: { hash: '' },
    addEventListener(name, fn) { events[name] = fn; },
    setTimeout(fn) { fn(); }
};
const document = {
    querySelectorAll(selector) { return selectors[selector] || []; },
    getElementById(id) { return targets[id] || null; }
};
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), { window, document });
highButton.handlers.click();
assert.equal(low.hidden, true);
events.beforeprint(); events.beforeprint();
assert.equal(low.hidden, false);
assert.equal(closed.open, true);
events.afterprint();
assert.equal(low.hidden, true);
assert.equal(closed.open, false);
assert.equal(opened.open, true);
events.afterprint(); // unmatched event is safe
window.location.hash = '#finding'; events.hashchange();
assert.equal(low.hidden, false);
assert.equal(low.scrolled, true);
window.location.hash = '#coverage'; link.handlers.click();
assert.equal(closed.open, true);
closed.open = false;
window.location.hash = '#child'; events.hashchange();
assert.equal(closed.open, true);
window.location.hash = '#%bad'; events.hashchange();
console.log('navigation/filter/disclosure/print restoration passed');
