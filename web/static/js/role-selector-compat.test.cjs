const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const legacy = '渗透测试';
const english = 'Penetration Testing';

function browser(script, apiFetch, element) {
    const saved = new Map([['currentRole', legacy]]);
    const context = vm.createContext({
        window: {}, console: { error() {}, warn() {} },
        document: {
            readyState: 'loading', addEventListener() {},
            getElementById: id => id === 'bq-role-val' ? element : null,
        },
        localStorage: { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) },
        apiFetch, showNotification() {},
        escapeAttr: value => String(value), escapeHtml: value => String(value),
    });
    vm.runInContext(fs.readFileSync(require.resolve('./i18n.js'), 'utf8'), context);
    context.window.i18nReady = Promise.resolve();
    vm.runInContext(fs.readFileSync(require.resolve('./' + script), 'utf8'), context);
    return { context, saved };
}

for (const [label, response] of [
    ['unavailable', () => { throw new Error('offline'); }],
    ['forbidden', () => ({ ok: false, status: 403 })],
    ['empty', () => ({ ok: true, json: async () => ({ roles: [] }) })],
]) {
    test(`role selection preserves a stored custom selector when catalog is ${label}`, async () => {
        const { context, saved } = browser('roles.js', response);
        await context.loadRoles();
        context.window.setCurrentRole(legacy);
        assert.equal(context.window.getCurrentRole(), legacy);
        assert.equal(saved.get('currentRole'), legacy);
        assert.equal(context.window.englishBundledRoleName(legacy, []), english);
    });
}

for (const [label, catalog, expected] of [
    ['confirmed bundled alias', [{ name: english }], english],
    ['exact custom precedence', [{ name: english }, { name: legacy }], legacy],
]) {
    test(`role selection honors ${label}`, async () => {
        const before = JSON.stringify(catalog);
        const { context, saved } = browser('roles.js', async () => ({ ok: true, json: async () => ({ roles: catalog }) }));
        await context.loadRoles();
        context.window.setCurrentRole(legacy);
        assert.equal(context.window.getCurrentRole(), expected);
        assert.equal(saved.get('currentRole'), expected);
        assert.equal(JSON.stringify(catalog), before);
    });
}

for (const [label, catalog, expected] of [
    ['missing catalog', undefined, legacy],
    ['empty catalog', [], legacy],
    ['exact custom role', [{ name: legacy }, { name: english }], legacy],
    ['confirmed bundled role', [{ name: english }], english],
]) {
    test(`batch role editor preserves machine option values with ${label}`, async () => {
        const element = { innerHTML: '', querySelector: () => null };
        const { context } = browser('tasks.js', async () => ({ json: async () => ({ queue: { role: legacy } }) }), element);
        context.testCatalog = catalog;
        vm.runInContext('batchQueuesState.currentQueueId = "fixture"; batchQueuesState.loadedRoles = testCatalog;', context);
        context.window.startInlineEditRole();
        // The public editor completes through its real asynchronous API path.
        await new Promise(resolve => setImmediate(resolve));
        assert.ok(element.innerHTML.includes(`value="${expected}" selected`), element.innerHTML);
        if (!catalog || catalog.length === 0) {
            assert.ok(element.innerHTML.includes(`>${english} (`), element.innerHTML);
            assert.ok(!element.innerHTML.includes(`value="${english}"`), element.innerHTML);
        }
    });
}
