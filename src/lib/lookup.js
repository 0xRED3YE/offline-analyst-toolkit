/*
 * lookup.js: reputation-site links for an indicator. The toolkit only builds the
 * links; the analyst decides whether to click (which sends the indicator to that site).
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).lookup = lib;
})(globalThis, function () {
  'use strict';

  const e = encodeURIComponent;

  const SERVICES = {
    ipv4: [
      ['VirusTotal', (v) => `https://www.virustotal.com/gui/ip-address/${e(v)}`],
      ['AbuseIPDB', (v) => `https://www.abuseipdb.com/check/${e(v)}`],
      ['Shodan', (v) => `https://www.shodan.io/host/${e(v)}`],
      ['urlscan', (v) => `https://urlscan.io/ip/${e(v)}`],
    ],
    domain: [
      ['VirusTotal', (v) => `https://www.virustotal.com/gui/domain/${e(v)}`],
      ['urlscan', (v) => `https://urlscan.io/domain/${e(v)}`],
      ['URLhaus', (v) => `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
      ['Shodan', (v) => `https://www.shodan.io/search?query=${e(`hostname:${v}`)}`],
    ],
    url: [
      ['VirusTotal', (v) => `https://www.virustotal.com/gui/search/${e(e(v))}`],
      ['URLhaus', (v) => `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
      ['urlscan (search)', (v) => `https://urlscan.io/search/#${e(`page.url:"${v}"`)}`],
    ],
    hash: [
      ['VirusTotal', (v) => `https://www.virustotal.com/gui/file/${e(v)}`],
      ['MalwareBazaar', (v) => `https://bazaar.abuse.ch/browse.php?search=${e(`${v.length === 64 ? 'sha256' : v.length === 40 ? 'sha1' : 'md5'}:${v}`)}`],
    ],
    cve: [
      ['NVD', (v) => `https://nvd.nist.gov/vuln/detail/${e(v)}`],
      ['CISA KEV', (v) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${e(v)}`],
    ],
    mitre: [
      ['MITRE ATT&CK', (v) => `https://attack.mitre.org/techniques/${v.replace('.', '/')}/`],
    ],
  };
  SERVICES.ipv6 = SERVICES.ipv4.filter(([name]) => name !== 'urlscan');
  SERVICES.md5 = SERVICES.hash;
  SERVICES.sha1 = SERVICES.hash;
  SERVICES.sha256 = SERVICES.hash;
  SERVICES.sha512 = [SERVICES.hash[0]];
  SERVICES.email = [];

  // [{ name, url }] for an indicator of the given type. Only https links are produced.
  function linksFor(type, value) {
    return (SERVICES[type] || []).map(([name, make]) => ({ name, url: make(value) }));
  }

  return { linksFor };
});
