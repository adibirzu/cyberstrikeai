const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Exercise the shipped browser initializer: an old Chinese preference, a
// Chinese browser, and a later legacy switch request must all stay English.
test('English runtime ignores browser and persisted vendor locale', async () => {
    const events = {};
    const requested = [];
    const labels = { 'current-lang-label': { textContent: '' } };
    const document = {
        documentElement: {},
        getElementById: id => labels[id] || null,
        querySelectorAll: () => [],
        querySelector: () => null,
        addEventListener: (name, fn) => { events[name] = fn; },
        dispatchEvent: () => {},
    };
    const i18next = {
        language: '',
        init: async options => { i18next.language = options.lng; },
        addResourceBundle: () => {},
        changeLanguage: async lang => { i18next.language = lang; },
        t: key => ({ 'lang.enUS': 'English' }[key] || key),
    };
    const window = {};
    vm.runInNewContext(fs.readFileSync(require.resolve('./i18n.js'), 'utf8'), {
        window, document, i18next, navigator: { language: 'zh-CN' },
        localStorage: { getItem: () => 'zh-CN', setItem: () => {} },
        fetch: async url => { requested.push(url); return { ok: true, json: async () => ({}) }; },
        console, CustomEvent: class {},
    });
    events.DOMContentLoaded();
    await window.i18nReady;
    assert.equal(document.documentElement.lang, 'en-US');
    assert.equal(window.uiLocale(), 'en-US');
    assert.equal(labels['current-lang-label'].textContent, 'English');
    await window.changeLanguage('zh-CN');
    assert.equal(i18next.language, 'en-US');
    assert.deepEqual(requested, ['/static/i18n/en-US.json']);
});

test('legacy role/account labels are presentation aliases and preserve custom data', () => {
    const window = {};
    vm.runInNewContext(fs.readFileSync(require.resolve('./i18n.js'), 'utf8'), {
        window, document: { addEventListener() {} }, localStorage: { getItem: () => null },
        console, navigator: { language: 'en-US' },
    });
    const input = '渗透测试';
    const catalog = [{ name: 'Penetration Testing' }];
    assert.equal(window.englishBundledRoleName(input, catalog), 'Penetration Testing');
    assert.equal(input, '渗透测试');
    assert.deepEqual(catalog, [{ name: 'Penetration Testing' }]);
    assert.equal(window.englishBundledRoleName(input, [{ name: input }]), input);
    assert.equal(window.englishBundledRoleName('target says 确认 role=admin', catalog), 'target says 确认 role=admin');
    const factory = { id: 'admin', username: 'admin', display_name: '管理员' };
    assert.equal(window.englishFactoryAccountName(factory), 'Administrator');
    assert.equal(factory.display_name, '管理员');
    assert.equal(window.englishFactoryAccountName({ ...factory, id: 'other-user' }), '管理员');
    assert.equal(window.englishFactoryAccountName({ ...factory, display_name: 'operator custom' }), 'operator custom');
});
