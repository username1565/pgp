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

    // SIGN
    var signButton = $("#sign-button");

    signButton.click(function(){
        var signPlainText = $("#sign-plain-text");
        var SignedText = $("#signed-text");
        var signPrivateKey = $("#sign-private-key");
        var signPassphrase = $("#sign-passphrase");

        var currUser = kbpgp.KeyManager.import_from_armored_pgp({
          armored: signPrivateKey.val()
        }, function(err, currUser) {
          if (!err) {
            if (currUser.is_pgp_locked()) {
              currUser.unlock_pgp({
                passphrase: signPassphrase.val()
              }, function(err) {
                if (!err) {
                  console.log("Loaded private key with passphrase");

                  var params = {
                    msg: signPlainText.val(),
                    sign_with: currUser
                  };

                  kbpgp.box(params, function(err, result_string, result_buffer) {
                    console.log(err, result_string, result_buffer);
                    SignedText.val(result_string);
                  });
                }
              });
            } else {
              console.log("Loaded private key w/o passphrase");
            }
          }
        });
  });

  // SIGN+Encrypt
  var signencryptButton = $("#signencrypt-button");

  signencryptButton.click(function() {
      var signencryptPlainText = $("#signencrypt-plain-text");
      var signencryptText = $("#signencrypt-text");
      var signencryptPrivateKey = $("#signencrypt-private-key");
      var signencryptPassphrase = $("#signencrypt-passphrase");
      var signencryptReceiversPublicKey = $("#signencrypt-receivers-public-key");

      var currUser = kbpgp.KeyManager.import_from_armored_pgp({
          armored: signencryptPrivateKey.val()
      }, function(err, currUser) {
          if (!err) {
              if (currUser.is_pgp_locked()) {
                  currUser.unlock_pgp({
                      passphrase: signencryptPassphrase.val()
                  }, function(err) {
                      if (!err) {
                          console.log("Loaded private key with passphrase");
                      }
                  });
              }
          }
          // import receiver's public key
          var receiver = kbpgp.KeyManager.import_from_armored_pgp({
              armored: signencryptReceiversPublicKey.val()
          }, function(err, receiver) {
              if (!err) {
                  console.log("receiver's public key is loaded");
                  console.log(receiver);

                  var params = {
                      msg: signencryptPlainText.val(),
                      sign_with: currUser,
                      encrypt_for: receiver
                  };

                  kbpgp.box(params, function(err, result_string, result_buffer) {
                      console.log(err, result_string, result_buffer);
                      signencryptText.val(result_string);
                  });
              } else {
                  console.log("Error!");
              }
          });
      });
  });

    /* New code by Matej Ramuta */

    // ENCRYPTION
    var encryptionButton = $("#encryption-button");

    encryptionButton.click(function(){
        var encryptionPlainText = $("#encryption-plain-text");
        var encryptionEncryptedText = $("#encryption-encrypted-text");
        var encryptionReceiversPublicKey = $("#encryption-receivers-public-key");

        // import receiver's public key
        var receiver = kbpgp.KeyManager.import_from_armored_pgp({
          armored: encryptionReceiversPublicKey.val()
        }, function(err, receiver) {
          if (!err) {
            console.log("receiver's public key is loaded");
            console.log(receiver);

            // encrypt the message
            var params = {
              msg: encryptionPlainText.val(),
              encrypt_for: receiver
            };

            kbpgp.box(params, function(err, result_string, result_buffer) {
              console.log(err, result_string, result_buffer);
              encryptionEncryptedText.val(result_string);
            });

          } else {
            console.log("Error!");
          }
        });
    });

    // DECRYPTION
    var decryptionButton = $("#decryption-button");

    decryptionButton.click(function(){
        var decryptionEncryptedText = $("#decryption-encrypted-text");
        var decryptionDecryptedText = $("#decryption-decrypted-text");
        var decryptionPrivateKey = $("#decryption-private-key");
        var decryptionPassphrase = $("#decryption-passphrase");
		var pgpFingerprint = $("#pgp-fingerprint");

        console.log(decryptionEncryptedText);

        // import receiver's public key
        var currUser = kbpgp.KeyManager.import_from_armored_pgp({
          armored: decryptionPrivateKey.val()
        }, function(err, currUser) {
          if (!err) {
            if (currUser.is_pgp_locked()) {
              currUser.unlock_pgp({
                passphrase: decryptionPassphrase.val()
              }, function(err) {
                if (!err) {
                  console.log("Loaded private key with passphrase");

                  // add KeyRing
                  var ring = new kbpgp.keyring.KeyRing;
                  ring.add_key_manager(currUser);

                  kbpgp.unbox({keyfetch: ring, armored: decryptionEncryptedText.val()}, function(err, literals) {
                    if (err != null) {
                      return console.log("Problem: " + err);
                    } else {
                      var decryptedText = literals[0].toString();
					  						document.getElementById("Fingerprint").reset();
                      console.log("decrypted message: " + decryptedText);

                      decryptionDecryptedText.val(decryptedText);

                      var ds = km = null;
                      ds = literals[0].get_data_signer();
                      if (ds) { km = ds.get_key_manager(); }
                      if (km) {
                        console.log("Signed by PGP fingerprint");
                        console.log(km.get_pgp_fingerprint().toString('hex'));
						var PGP = "PGP Fingerprint: "
						var Fingerprint = km.get_pgp_fingerprint().toString('hex');
						pgpFingerprint.val(PGP.concat(Fingerprint));
                      }
                    }
                  });

                } else {
                  console.log("Error in decryption unlock pgp");
                }
              });
            } else {
              console.log("Loaded private key w/o passphrase");
            }
          } else {
            console.log("Error in decryption import");
          }
        });
    });
});
