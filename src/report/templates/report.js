(function () {
    // Severity filter: optional convenience; the report is complete without JavaScript.
    var buttons = document.querySelectorAll('.filter');
    var currentFilter = 'all';
    var printState = null;
    function applyFilter(value) {
        currentFilter = value;
        document.querySelectorAll('[data-severity]').forEach(function (element) {
            element.hidden = value !== 'all' && element.getAttribute('data-severity') !== value;
        });
        buttons.forEach(function (button) {
            button.classList.toggle('active', button.getAttribute('data-filter') === value);
        });
    }
    buttons.forEach(function (button) {
        button.addEventListener('click', function () { applyFilter(button.getAttribute('data-filter')); });
    });
    document.querySelectorAll('.tile[data-filter]').forEach(function (tile) {
        tile.addEventListener('click', function () { applyFilter(tile.getAttribute('data-filter')); });
    });
    function revealTarget() {
        var id;
        try { id = decodeURIComponent(window.location.hash.slice(1)); } catch (_) { return; }
        var target = document.getElementById(id);
        if (!target) { return; }
        var node = target;
        while (node) {
            if (node.matches && node.matches('details')) { node.open = true; }
            if (node.matches && node.matches('[data-severity]') && node.hidden) { applyFilter('all'); }
            node = node.parentElement;
        }
        var disclosure = target.querySelector('details');
        if (disclosure) { disclosure.open = true; }
        target.scrollIntoView();
    }
    window.addEventListener('hashchange', revealTarget);
    document.querySelectorAll('a[href^="#"]').forEach(function (link) {
        link.addEventListener('click', function () { window.setTimeout(revealTarget, 0); });
    });
    revealTarget();
    // Expand for print, then restore the user's disclosure/filter selection.
    window.addEventListener('beforeprint', function () {
        if (!printState) {
            printState = { filter: currentFilter, disclosures: [] };
            document.querySelectorAll('details').forEach(function (details) {
                printState.disclosures.push({ element: details, open: details.open });
            });
        }
        applyFilter('all');
        document.querySelectorAll('details').forEach(function (details) { details.open = true; });
    });
    window.addEventListener('afterprint', function () {
        if (!printState) { return; }
        printState.disclosures.forEach(function (item) { item.element.open = item.open; });
        applyFilter(printState.filter);
        printState = null;
    });
})();
