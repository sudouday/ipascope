(function (root) {
'use strict';

// Builds a trimmed copy of the in-memory results object suitable for sending
// to the optional share backend (server/). It's the same shape renderAll()
// already expects, minus fields a viewer link doesn't need:
//   - `macho`: the full raw load-command dump (UI only reads `machoSummary`)
//   - `appIcon`: dropped if it pushes the payload past a sane size, since it's
//     cosmetic, not a finding
// Nothing here re-hosts the original .ipa or its raw bytes — those were never
// part of the in-memory `results` object to begin with.
// Human-readable severity labels for the internal keys (matches the app UI).
var SEV_LABEL = { high: 'High', warning: 'Medium', info: 'Low', secure: 'Info' };

function buildShareable(results) {
    const { macho, ...rest } = results;
    let shareable = { ...rest, shared: true };
    const withIcon = JSON.stringify(shareable);
    if (withIcon.length > 1_500_000 && shareable.appIcon) {
        const { appIcon, ...withoutIcon } = shareable;
        shareable = withoutIcon;
    }
    return shareable;
}

function toJSON(results) {
    const json = {
        tool: { name: 'IPAScope', version: '0.4.0' },
        generatedAt: new Date().toISOString(),
        app: results.appInfo,
        plist: results.plistData,
        permissions: results.permissions,
        urlSchemes: results.urlSchemes,
        queriedSchemes: results.queriedSchemes,
        ats: results.ats,
        provisioning: results.provisioning ? {
            meta: results.provisioning.meta,
            entitlementCount: results.provisioning.entitlementCount,
            entitlementKeys: results.provisioning.entitlementKeys,
            certificates: (results.provisioning.certificates || []).map(c => ({
                subjectCN: c.subjectCN, issuerCN: c.issuerCN,
                validity: c.validity, serial: c.serial,
            })),
            distribution: results.provisioning.meta?.distribution,
        } : null,
        macho: results.machoSummary,
        entitlementsXml: results.entitlementsXml,
        trackers: results.trackers,
        libraries: results.libraries,
        urls: results.urls,
        emails: results.emails,
        summary: results.summary,
        securityScore: results.securityScore,
        findings: results.findings.map(f => ({
            ruleId: f.ruleId,
            ruleName: f.ruleName,
            severity: f.severity,
            confidence: f.confidence,
            confidenceLabel: f.confidenceLabel,
            entropy: f.entropy,
            description: f.description,
            cwe: f.cwe, owasp: f.owasp, masvs: f.masvs, mitre: f.mitre,
            category: f.category,
            file: f.file,
            line: f.line,
            match: f.match,
            binaryOffset: f.binaryOffset,
            snippet: f.snippet,
        })),
    };
    return JSON.stringify(json, null, 2);
}

function csvEscape(v) {
    if (v == null) return '';
    const s = String(v);
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

function toCSV(results) {
    const rows = [
        ['severity', 'confidence', 'rule_id', 'rule_name', 'category', 'cwe', 'owasp', 'masvs', 'mitre', 'file', 'line', 'match', 'binary_offset', 'description'],
    ];
    for (const f of results.findings) {
        rows.push([
            SEV_LABEL[f.severity] || f.severity, f.confidence ?? '', f.ruleId, f.ruleName, f.category || '',
            f.cwe || '', f.owasp || '', f.masvs || '', f.mitre || '',
            f.file || '', f.line ?? '',
            (f.match || '').slice(0, 500),
            f.binaryOffset || '',
            (f.description || '').slice(0, 500),
        ]);
    }
    return rows.map(r => r.map(csvEscape).join(',')).join('\n');
}

function severityToSarifLevel(s) {
    switch (s) {
        case 'high':    return 'error';
        case 'warning': return 'warning';
        case 'info':    return 'note';
        case 'secure':  return 'note';
        default:        return 'none';
    }
}

function toSARIF(results) {
    const rules = new Map();
    const sarifResults = [];
    for (const f of results.findings) {
        if (!rules.has(f.ruleId)) {
            rules.set(f.ruleId, {
                id: f.ruleId,
                name: f.ruleName,
                shortDescription: { text: f.ruleName },
                fullDescription: { text: f.description || f.ruleName },
                helpUri: f.cwe ? 'https://cwe.mitre.org/data/definitions/' + (f.cwe.replace(/^CWE-/, '')) + '.html' : undefined,
                defaultConfiguration: { level: severityToSarifLevel(f.severity) },
                properties: {
                    severity: f.severity,
                    cwe: f.cwe,
                    owasp: f.owasp,
                    masvs: f.masvs,
                    mitre: f.mitre,
                    category: f.category,
                },
            });
        }
        const physical = f.binaryOffset
            ? { artifactLocation: { uri: f.file }, region: { byteOffset: parseInt(f.binaryOffset, 16) || 0 } }
            : { artifactLocation: { uri: f.file }, region: f.line ? { startLine: f.line } : undefined };
        sarifResults.push({
            ruleId: f.ruleId,
            level: severityToSarifLevel(f.severity),
            message: { text: f.description || f.ruleName },
            locations: f.file ? [{ physicalLocation: physical }] : [],
            properties: {
                confidence: f.confidence,
                entropy: f.entropy,
                match: (f.match || '').slice(0, 200),
            },
        });
    }
    return JSON.stringify({
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'IPAScope',
                    version: '0.4.0',
                    informationUri: 'https://ipascope.com',
                    rules: [...rules.values()],
                },
            },
            artifacts: [{
                location: { uri: results.appInfo?.fileName },
                hashes: results.appInfo?.sha256 ? { 'sha-256': results.appInfo.sha256 } : undefined,
            }],
            results: sarifResults,
            properties: {
                securityScore: results.securityScore,
                summary: results.summary,
                app: results.appInfo,
            },
        }],
    }, null, 2);
}

function download(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 1000);
}

function exportFile(kind, results, filenameBase) {
    const base = filenameBase || (results.appInfo?.appName || 'ipa') + '_' + (results.appInfo?.version || '');
    const safeBase = base.replace(/[^a-zA-Z0-9._-]/g, '_');
    if (kind === 'json')  return download(toJSON(results),  safeBase + '_report.json',  'application/json');
    if (kind === 'csv')   return download(toCSV(results),   safeBase + '_findings.csv', 'text/csv');
    if (kind === 'sarif') return download(toSARIF(results), safeBase + '_findings.sarif', 'application/json');
    throw new Error('Unknown export kind: ' + kind);
}

const api = { toJSON, toCSV, toSARIF, exportFile, buildShareable };

if (typeof module !== 'undefined' && module.exports) module.exports = api;
else {
    root.IPAS = root.IPAS || {};
    root.IPAS.Export = api;
}

})(typeof self !== 'undefined' ? self : this);
