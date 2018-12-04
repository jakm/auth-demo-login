$(function() {
    $.getScript('https://connect.trezor.io/6/trezor-connect.js')
    .done(function(data, status, jqXhr) {
        login();
    })
    .fail(function(jqXhr, status, errorMessage) {
        $('body').hide();
        alert("Resource unavailable: " + this.url + ": " + errorMessage);
    })
});

function login() {
    let urlParams = new URLSearchParams(window.location.search);
    let formMessages = $('#form-messages')

    function setErrorMessage(error) {
        console.log(error);

        $(formMessages).attr('class', 'notify-error');
        $(formMessages).text('Login failed');
    }

    if (!urlParams.has('login_challenge')) {
        setErrorMessage('invalid parameters');
        return;
    }

    let challenge = urlParams.get('login_challenge');

    $.ajax({
        type: 'GET',
        url: '/login/challenge/' + challenge,
        contentType: 'application/json'
    })
    .done(function(data, status, jqXhr) {
        TrezorConnect.requestLogin(data).then(function(result) {
            if (result.success == false) {
                setErrorMessage('request login: ' + result.payload.error);
            } else {
                $.ajax({
                    type: 'POST',
                    url: '/login/verify/' + challenge,
                    dataType: 'json',
                    data: {
                        'address': result.payload.address,
                        'publicKey': result.payload.publicKey,
                        'signature': result.payload.signature
                    }
                })
                .done(function(data, status, jqXhr) {
                    switch (jqXhr.status) {
                        case 200:
                            window.location.replace(data.redirect_to);
                            break;
                        default:
                            setErrorMessage('invalid response status: ' + jqXhr.status);
                    }
                })
                .fail(function(jqXhr, status, error) {
                    setErrorMessage('verification error: ' + jqXhr.status);
                })
            }
        });
    })
    .fail(function(jqXhr, status, error) {
        setErrorMessage('get device challenge: ' + jqXhr.status);
    })
}
