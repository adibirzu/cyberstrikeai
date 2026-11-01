const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const chat = fs.readFileSync(require.resolve('./chat.js'), 'utf8');
const monitor = fs.readFileSync(require.resolve('./monitor.js'), 'utf8');

function block(source, start, end) {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from);
    assert.ok(from >= 0 && to > from);
    return source.slice(from, to);
}

for (const [name, data, expected] of [
    ['main agent', { einoScope: 'main', iteration: 7 }, 'Orchestrator · round 7'],
    ['sub-agent', { einoScope: 'sub', einoAgent: 'fixture', iteration: 3 }, 'Sub-agent fixture · step 3'],
    ['generic iteration', { iteration: 4 }, 'Iteration 4'],
    ['plan-execute', { einoScope: 'main', orchestration: 'plan_execute', einoAgent: 'planner', iteration: 2 }, 'Plan-Execute · round 2 · planner'],
]) {
    test(`restored and live ${name} labels remain meaningful before i18n is ready`, () => {
        const titles = [];
        const context = vm.createContext({
            window: {}, timeline: {}, prependMode: false,
            processDetailAgentPrefix: () => '',
            addTimelineItem: (_timeline, _type, options) => { titles.push(options.title); },
            mainIterationStateByProgressId: new Map(),
            translatePlanExecuteAgentName: name => name,
            clearTimelineStreamStates() {}, dispatchAgentPlanTaskEvent() {},
            resolveStreamTimeline: () => ({}), scrollChatMessagesToBottomIfPinned() {},
        });
        vm.runInContext(block(chat, '    function renderOneProcessDetail(', '    function finishPrependRender('), context);
        vm.runInContext(block(monitor, 'function handleStreamEvent(', 'function hitlApprovalTranslate('), context);
        context.renderOneProcessDetail({ eventType: 'iteration', data });
        context.handleStreamEvent({ type: 'iteration', data }, {}, 'fixture');
        assert.deepEqual(titles, [expected, expected]);
    });
}

test('pruned timeline fallback retains count and exact round range', () => {
    const context = vm.createContext({ window: {} });
    vm.runInContext(block(monitor, 'function formatLiveTimelinePrunedMarker(', 'function pruneLiveTimelineIfNeeded('), context);
    const format = (min, max) => context.formatLiveTimelinePrunedMarker({ dataset: {
        prunedCount: '12', prunedMainIterationMin: String(min), prunedMainIterationMax: String(max),
    } });
    const base = 'Collapsed the first 12 live process details. View the full record page by page after the task completes.';
    assert.equal(format(0, 0), base);
    assert.equal(format(2, 2), base + ' · main-agent round 2');
    assert.equal(format(2, 5), base + ' · main-agent rounds 2–5');
});
