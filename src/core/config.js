(function (root) {
'use strict';

// Leave API_BASE empty to keep IPAScope 100% client-side, no backend contacted
// ever, matching the default behavior of the whole app. Only set this if you've
// deployed server/ (see server/README.md) and want the "Share Report" export
// option to work for visitors of this deployment.
//
// Example: API_BASE: 'https://share.ipascope.com'
const Config = {
    API_BASE: '',
};

root.IPAS = root.IPAS || {};
root.IPAS.Config = Config;

})(typeof self !== 'undefined' ? self : this);
