// Reads the search term from the JSON data block on the secure search page
// and shows it with textContent, so the browser treats it as plain text.
(function () {
  var el = document.getElementById('search-data');
  var out = document.getElementById('last-search');
  if (!el || !out) return;
  var data = JSON.parse(el.textContent);
  out.textContent = data.q;
})();
