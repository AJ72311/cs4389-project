const switchButton = document.getElementById('mode-switch');
if (switchButton) {
    switchButton.addEventListener('click', () => {
        fetch('/mode/toggle', {method: 'POST'}).then(() => location.reload());
    });
}

function show(url, outputId, options) {
    fetch(url, options)
        .then(response => response.json())
        .then(data => {
            document.getElementById(outputId).textContent = JSON.stringify(data, null, 2);
        });
}

document.querySelectorAll('form[data-api]').forEach(form => {
    form.addEventListener('submit', event => {
        event.preventDefault();
        const query = new URLSearchParams(new FormData(form)).toString();
        show(form.dataset.api + '?' + query, form.dataset.output);
    });
});

document.querySelectorAll('button[data-select]').forEach(button => {
    button.addEventListener('click', () => {
        show(document.getElementById(button.dataset.select).value, button.dataset.output);
    });
});

document.querySelectorAll('button[data-post]').forEach(button => {
    button.addEventListener('click', () => {
        show(button.dataset.post, button.dataset.output, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: button.dataset.body
        });
    });
});

document.querySelectorAll('button[data-raw]').forEach(button => {
    button.addEventListener('click', () => {
        fetch(button.dataset.raw).then(response => {
            const headers = [];
            response.headers.forEach((value, name) => headers.push(name + ': ' + value));
            return response.text().then(body => {
                document.getElementById(button.dataset.output).textContent =
                    'HTTP ' + response.status + '\n' + headers.join('\n') + '\n\n' + body;
            });
        });
    });
});
