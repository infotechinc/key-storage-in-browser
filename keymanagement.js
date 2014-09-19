// Key Management with Web Cryptography API
//
// Copyright 2014 Info Tech, Inc.
// Provided under the MIT license.
// See LICENSE file for details.

// Creates and saves key pairs. Requires keystore.js to be loaded first.

document.addEventListener("DOMContentLoaded", function() {
    "use strict";

    if (!window.crypto || !window.crypto.subtle) {
        alert("Your current browser does not support the Web Cryptography API! This page will not work.");
        return;
    }

    if (!window.indexedDB) {
        alert("Your current browser does not support IndexedDB. This page will not work.");
        return;
    }

    var keyStore = new KeyStore();
    keyStore.open().
    then(function() {
        document.getElementById("create-key").addEventListener("click", handleCreateKeyPairClick);
        populateKeyListing(keyStore);
    }).
    catch(function(err) {
        alert("Could not open key store: " + err.message)
    });


    function populateKeyListing(keyStore) {
        keyStore.listKeys().
        then(function(list) {
            for (var i=0; i<list.length; i++) {
                addToKeyList(list[i].value);
            }
        }).
        catch(function(err) {
            alert("Could not list keys: " + err.message);
        });
    }


    function addToKeyList(savedObject) {
        var dataUrl = createDataUrlFromByteArray(new Uint8Array(savedObject.spki));
        var name = escapeHTML(savedObject.name);

        document.getElementById("list-keys").insertAdjacentHTML(
            'beforeEnd',
            '<li><a download="' + name + '.publicKey" href="' + dataUrl + '">' + name + '</a></li>');
    }



    // Key pair creation section
    function handleCreateKeyPairClick() {
        var algorithmName, usages;

        var name = document.getElementById("created-key-name").value;
        if (!name) {
            alert("Must specify a name for the new key.");
            return;
        }

        // Depending on whether it is a signing key or an encrypting
        // key, different algorithmNames and usages are needed to
        // generate the new key pair.
        var selection = document.getElementsByName("created-key-type");
        if (selection[0].checked) { // Signing key
            algorithmName = "RSASSA-PKCS1-v1_5";
            usages = ["sign", "verify"];
        } else if (selection[1].checked) { // Encrypting key
            algorithmName = "RSA-OAEP";
            usages = ["encrypt", "decrypt"];
        } else {
            alert("Must select kind of key first.");
            return;
        }

        window.crypto.subtle.generateKey(
            {
                name: algorithmName,
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),  // 24 bit representation of 65537
                hash: {name: "SHA-256"}
            },
            false,  // Cannot extract new key
            usages
        ).
        then(function(keyPair) {
            return keyStore.saveKey(keyPair.publicKey, keyPair.privateKey, name);
        }).
        then(addToKeyList).
        catch(function(err) {
            alert("Could not create and save new key pair: " + err.message);
        });
    }



    // Utility functions

    function escapeHTML(s) {
        return s.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
    }

    function createDataUrlFromByteArray(byteArray) {
        var binaryString = '';
        for (var i=0; i<byteArray.byteLength; i++) {
            binaryString += String.fromCharCode(byteArray[i]);
        }
        return "data:application/octet-stream;base64," + btoa(binaryString);
    }
});
