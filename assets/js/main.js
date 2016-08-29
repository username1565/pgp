$(document).ready(function() {
    /* Dynamic key size menus */
    $('#algorithm').change(function() {
        populateKeysizeDropdown();
        $('#bitlength').removeAttr('disabled');
    });

    /* Set event handlers */
    $('form#keygen').submit(function(e) {
        e.preventDefault();
        genKeyPair();
    });

    $('#download_priv_key').on('click', downloadPrivKey);
    $('#download_pub_key').on('click', downloadPubKey);

    $('#name, #email, #comments, #algorithm, #bitlength, #expire, #passphrase').tooltip({
        trigger: 'hover',
        placement: 'top'
    });

    $('[data-toggle="popover"]').popover({placement: 'top'});

    /* New code by Matej Ramuta */
    var encryptionButton = $("#encryption-button");

    encryptionButton.click(function(){
        var encryptionPlainText = $("#encryption-plain-text");
        var encryptionEncryptedText = $("#encryption-encrypted-text");
        var encryptionReceiversPublicKey = $("#encryption-receivers-public-key");

        // import receiver's public key
        var matt = kbpgp.KeyManager.import_from_armored_pgp({
          armored: encryptionReceiversPublicKey.val()
        }, function(err, matt) {
          if (!err) {
            console.log("matt's public key is loaded");
            console.log(matt);

            // encrypt the message
            var params = {
              msg: encryptionPlainText.val(),
              encrypt_for: matt
            };

            kbpgp.box(params, function(err, result_string, result_buffer) {
              console.log(err, result_string, result_buffer);
              encryptionEncryptedText.val(result_string);
            });

          } else {
            console.log("Error!");
          }
        });

        console.log(matt);


    });
});