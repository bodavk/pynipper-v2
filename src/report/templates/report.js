(function () {
    // Severity filter: optional convenience; the report is complete without JavaScript.
    var buttons = document.querySelectorAll('.filter');
    function applyFilter(value) {
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
    // Printed reports should include the collapsed background sections.
    window.addEventListener('beforeprint', function () {
        applyFilter('all');
        document.querySelectorAll('details').forEach(function (details) { details.open = true; });
    });
})();
