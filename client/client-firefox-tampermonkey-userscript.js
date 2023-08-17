// ==UserScript==
// @name         Close Tab on Load
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  Close the current tab once it loads completely
// @author       You
// @match        *://*/*
// @grant        GM_openInTab
// ==/UserScript==

let seconds = 2;

(function() {
    'use strict';

    window.addEventListener('load', function() {
        console.log('Page fully loaded')

        setTimeout(function() {
            window.close();
        }, 1000 * seconds);
    });

})();