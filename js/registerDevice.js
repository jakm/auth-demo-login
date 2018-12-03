$(function() {
    $.getScript('https://connect.trezor.io/6/trezor-connect.js')
    .done(function(data, status, jqXhr) {
        $('#btn-add-device').on('click', addDevice);
    })
    .fail(function(jqXhr, status, errorMessage) {
        $('body').hide();
        alert("Resource unavailable: " + this.url + ": " + errorMessage);
    })

    $('#device-registration-form').submit(function(event) {
        if ($('#device-list > li').length == 0) {
            let formMessages = $('#form-messages');
            $(formMessages).addClass('notify-error');
            $(formMessages).text('No device added')
            event.preventDefault();
        }
    });

});

function addDevice() {
    let registeredDevices = $('#registered-devices');
    let deviceList = $('#device-list');
    let formMessages = $('#form-messages');

    let label = $("#device-registration-form :input[name='label']");
    let challenge = $("#device-registration-form :input[name='challenge']");

    if (isEmpty($(label).val())) {
        $(formMessages).addClass('notify-error');
        $(formMessages).text('Please fill out device label');
        return;
    }

    function setErrorMessage(error) {
        console.log(error);

        $(formMessages).addClass('notify-error');
        $(formMessages).text('Device registration failed');
    };

    $.ajax({
        type: 'GET',
        url: '/register/device/' + $(challenge).val(),
        contentType: 'application/json'
    })
    .done(function(data, status, jqXhr) {
        TrezorConnect.requestLogin(data).then(function(result) {
            if (result.success == false) {
                setErrorMessage('request login: ' + result.payload.error);
            } else {
                $.ajax({
                    type: 'POST',
                    url: '/register/device/verify/' + $(challenge).val(),
                    dataType: 'json',
                    data: {
                        'label': $(label).val(),
                        'address': result.payload.address,
                        'publicKey': result.payload.publicKey,
                        'signature': result.payload.signature
                    }
                })
                .done(function(data, status, jqXhr) {
                    switch (jqXhr.status) {
                        case 201:
                            $(registeredDevices).show();
                            $(deviceList).append('<li>' + data.deviceLabel + ': ' + data.deviceID + '</li>');
                            $(formMessages).addClass('notify-success');
                            $(formMessages).text('Device added');
                            break;
                        default:
                            setErrorMessage('invalid response status: ' + jqXhr.statusText);
                    }
                })
                .fail(function(jqXhr, status, error) {
                    switch (jqXhr.status) {
                        case 403:
                            setErrorMessage('device verification failed');
                            break;
                        case 409:
                            setErrorMessage('device already registered');
                            break;
                        default:
                            setErrorMessage('invalid response status: ' + jqXhr.statusText);
                    }
                })
            }
        });
    })
    .fail(function(jqXhr, status, error) {
        setErrorMessage('get device challenge: ' + error);
    })
}

function isEmpty(s) {
    return s == null || s == ""
}
