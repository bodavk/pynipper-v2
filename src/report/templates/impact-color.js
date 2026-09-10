document.querySelectorAll('#vulnTable td.cvssValue').forEach(function(cell) {
    const value = Number.parseFloat(cell.textContent);
    if (Number.isNaN(value)) {
        return;
    }
    cell.style.backgroundColor = value >= 7 ? 'red' : value < 4 ? 'green' : 'yellow';
});
