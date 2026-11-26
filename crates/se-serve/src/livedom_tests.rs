//! The JS-side live DOM (`livedom.js`), driven through a real render pass.

use super::*;

pub(super) fn render_opts(html: &str, live: bool, ms: u64) -> (RenderStats, String) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = Engine::default();
    engine.tabs.lock().unwrap().insert(
        "default".to_string(),
        Tab::after_navigation(None, "https://example.test/a/b?x=1", String::new(), html.to_string()),
    );
    let opts = JsOpts { prelude: true, live_dom: live, quiesce: 3, ..JsOpts::default() };
    let stats = rt.block_on(JS_OPTS.scope(
        opts,
        engine.render_tab("default", std::time::Duration::from_millis(ms)),
    ));
    let out = engine.tabs.lock().unwrap().get("default").unwrap().html.clone();
    (stats, out)
}

/// Run `body` as the page's only script; it reports through `ok(name, cond)`
/// and the test reads back the names that failed.
fn check(markup: &str, body: &str) -> Vec<String> {
    let html = format!(
        "<!doctype html><html><head><title>T</title></head><body>{markup}<script>\
         var __f = []; function ok(n, c) {{ if (!c) __f.push(n); }}\
         try {{ {body} }} catch (e) {{ __f.push('threw: ' + (e && e.stack || e)); }}\
         var __o = document.createElement('pre'); __o.id = 'result'; \
         __o.textContent = 'FAILS[' + __f.join(' ;; ') + ']'; document.body.appendChild(__o);\
         </script></body></html>"
    );
    let (stats, out) = render_opts(&html, true, 1500);
    assert!(stats.page_errors.is_empty(), "page errors: {:?}", stats.page_errors);
    let at = out
        .find("<pre id=\"result\">FAILS[")
        .unwrap_or_else(|| panic!("no result in {out} / {:?}", stats.errors));
    let rest = &out[at + 23..];
    let end = rest.find("]</pre>").expect("result end");
    rest[..end]
        .split(" ;; ")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn created_and_parsed_nodes_have_a_tree_and_one_identity() {
    let fails = check(
        "<div id='a'><span class='s'>one</span>two<!--c--><b>three</b></div>",
        r#"
        var a = document.getElementById('a');
        ok('identity', a === document.getElementById('a') && a === document.querySelector('#a'));
        ok('childNodes', a.childNodes.length === 4 && a.childNodes[1].nodeType === 3 && a.childNodes[2].nodeType === 8);
        ok('first/last', a.firstChild.className === 's' && a.lastChild.tagName === 'B');
        ok('siblings', a.firstChild.nextSibling.data === 'two' && a.lastChild.previousSibling.nodeType === 8);
        ok('parent', a.firstChild.parentNode === a && a.parentElement === document.body);
        ok('ownerDocument', a.ownerDocument === document && document.ownerDocument === null);
        ok('expando survives', (a.firstChild.__x = 7, document.querySelector('.s').__x === 7));
        var d = document.createElement('div');
        ok('created empty tree', d.childNodes.length === 0 && d.firstChild === null && d.nodeType === 1 && d.ownerDocument === document);
        var t = document.createTextNode('hi'), c = document.createComment('k');
        d.appendChild(t); d.appendChild(c);
        ok('created children', d.childNodes.length === 2 && d.firstChild === t && t.nextSibling === c && c.parentNode === d);
        ok('isConnected', !d.isConnected && a.isConnected);
        var f = document.createDocumentFragment();
        f.appendChild(document.createElement('i')); f.appendChild(document.createElement('u'));
        a.appendChild(f);
        ok('fragment moves', f.childNodes.length === 0 && a.lastChild.tagName === 'U' && a.childNodes.length === 6);
        var b = a.querySelector('b');
        a.insertBefore(d, b);
        ok('insertBefore', b.previousSibling === d && d.parentNode === a);
        var old = a.replaceChild(document.createElement('em'), d);
        ok('replaceChild', old === d && d.parentNode === null && b.previousSibling.tagName === 'EM');
        a.removeChild(b);
        ok('removeChild', b.parentNode === null && !a.contains(b));
        var threw = false; try { a.removeChild(b); } catch (e) { threw = e.name === 'NotFoundError'; }
        ok('removeChild throws', threw);
        var cl = a.cloneNode(true);
        ok('cloneNode', cl !== a && cl.childNodes.length === a.childNodes.length && cl.firstChild !== a.firstChild && cl.firstChild.className === 's' && cl.parentNode === null);
        ok('shallow clone', a.cloneNode(false).childNodes.length === 0);
        ok('instanceof', a instanceof HTMLDivElement && a instanceof HTMLElement && a instanceof Element && a instanceof Node && t instanceof Text);
        ok('compare', (a.compareDocumentPosition(a.firstChild) & 16) === 16 && (a.firstChild.compareDocumentPosition(a) & 8) === 8);
        ok('doc parts', document.documentElement.tagName === 'HTML' && document.head.tagName === 'HEAD' && document.body.tagName === 'BODY' && document.title === 'T' && document.doctype.name === 'html');
        "#,
    );
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn inner_html_attributes_class_list_dataset_and_style_are_live() {
    let fails = check(
        "<div id='a' data-user-id='7' style='color: red'></div><table><tbody id='tb'></tbody></table><select id='sel'></select>",
        r#"
        var a = document.getElementById('a');
        a.innerHTML = "<p class='x y'>one &amp; <b>two</b></p><p>three</p>";
        ok('innerHTML set', a.childNodes.length === 2 && a.firstChild.firstChild.data === 'one & ');
        ok('innerHTML get', a.innerHTML === '<p class="x y">one &amp; <b>two</b></p><p>three</p>');
        ok('outerHTML', a.lastChild.outerHTML === '<p>three</p>');
        ok('textContent', a.textContent === 'one & twothree');
        a.lastChild.textContent = '<i>';
        ok('textContent set escapes', a.lastChild.innerHTML === '&lt;i&gt;' && a.lastChild.firstChild.nodeType === 3);
        var p = a.firstChild;
        p.classList.add('z'); p.classList.remove('x'); p.classList.toggle('q');
        ok('classList', p.className === 'y z q' && p.classList.contains('z') && !p.classList.contains('x') && p.classList.length === 3);
        ok('dataset', a.dataset.userId === '7' && (a.dataset.fooBar = 'v', a.getAttribute('data-foo-bar') === 'v'));
        ok('style read', a.style.color === 'red');
        a.style.display = 'none'; a.style.setProperty('margin-top', '2px'); a.style.backgroundColor = 'blue';
        ok('style write', /display: none/.test(a.getAttribute('style')) && a.style.marginTop === '2px' && a.style.getPropertyValue('background-color') === 'blue');
        a.style.display = '';
        ok('style remove', !/display/.test(a.getAttribute('style')));
        a.setAttribute('Title', 'T');
        ok('attributes', a.getAttribute('title') === 'T' && a.title === 'T' && a.hasAttribute('TITLE') && a.attributes.length >= 3);
        a.removeAttribute('title');
        ok('removeAttribute', a.getAttribute('title') === null && !a.hasAttribute('title'));
        ok('matches/closest', p.matches('div > p.y') && p.closest('#a') === a && p.firstElementChild.closest('body') === document.body && !p.matches('span'));
        var tb = document.getElementById('tb');
        tb.innerHTML = '<tr><td>1</td><td>2</td></tr>';
        ok('table rows keep their tags', tb.firstChild.tagName === 'TR' && tb.firstChild.childNodes.length === 2);
        var sel = document.getElementById('sel');
        sel.innerHTML = '<option value="a">A</option><option value="b" selected>B</option>';
        ok('select', sel.options.length === 2 && sel.value === 'b' && sel.selectedIndex === 1);
        a.insertAdjacentHTML('beforeend', '<span id="adj">x</span>');
        ok('insertAdjacentHTML', a.lastChild.id === 'adj');
        var tpl = document.createElement('template');
        tpl.innerHTML = '<li>a</li><li>b</li>';
        ok('template content', tpl.content.nodeType === 11 && tpl.content.childNodes.length === 2 && tpl.childNodes.length === 0);
        var inp = document.createElement('input');
        inp.setAttribute('type', 'checkbox'); inp.checked = true; inp.value = 'v';
        ok('input state', inp.checked === true && inp.value === 'v' && inp.cloneNode(true).checked === true && inp.type === 'checkbox');
        var link = document.createElement('a'); link.setAttribute('href', '../up?q=1#h');
        ok('href resolves', link.href === 'https://example.test/up?q=1#h' && link.pathname === '/up' && link.hash === '#h');
        "#,
    );
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn selectors_events_and_document_implementation_work() {
    let fails = check(
        "<ul id='l'><li class='a'>1</li><li class='b' data-k='v w'>2</li><li class='a b'>3</li></ul><form id='f'><input name='n' disabled><input type='checkbox' checked></form>",
        r#"
        var q = function (s) { return document.querySelectorAll(s).length; };
        ok('basic', q('li') === 3 && q('.a') === 2 && q('li.a.b') === 1 && q('#l > li') === 3 && q('ul li + li') === 2 && q('li ~ li.b') === 2);
        ok('attr', q('[data-k]') === 1 && q('[data-k~=w]') === 1 && q('[data-k^="v"]') === 1 && q('[data-k$=w]') === 1 && q('[data-k*=" "]') === 1 && q('[data-k^=""]') === 0 && q('[name=n]') === 1);
        ok('pseudo', q('li:first-child') === 1 && q('li:last-child') === 1 && q('li:nth-child(2n+1)') === 2 && q('li:nth-child(odd)') === 2 && q('li:not(.a)') === 1 && q(':checked') === 1 && q(':disabled') === 1 && q('input:enabled') === 1);
        ok('has/is', q('ul:has(> li.b)') === 1 && q('li:is(.a, .b)') === 3 && q('html:root') === 1);
        ok('list', q('li.a, input') === 4);
        var threw = 0;
        ['li:visible', 'li:eq(0)', '[a!=b]', '', 'li >', 'a::before', ':x'].forEach(function (s) { try { document.querySelectorAll(s); } catch (e) { if (e.name === 'SyntaxError') threw++; } });
        ok('bad selectors throw SyntaxError ' + threw, threw === 7);
        ok('scoped', document.getElementById('l').querySelector(':scope > li.b').textContent === '2');
        ok('collections', document.getElementsByTagName('li').length === 3 && document.getElementsByClassName('a b').length === 1 && document.forms.length === 1 && document.getElementById('f').elements.length === 2);
        var log = [];
        var ul = document.getElementById('l'), li = ul.firstElementChild;
        document.addEventListener('ping', function (e) { log.push('doc-capture:' + e.eventPhase); }, true);
        ul.addEventListener('ping', function (e) { log.push('ul:' + (e.target === li) + ':' + (e.currentTarget === ul)); });
        li.addEventListener('ping', function (e) { log.push('li'); });
        window.addEventListener('ping', function (e) { log.push('win:' + e.detail.n); });
        var ev = new CustomEvent('ping', { bubbles: true, cancelable: true, detail: { n: 5 } });
        var ret = li.dispatchEvent(ev);
        ok('event order ' + log.join(','), log.join(',') === 'doc-capture:1,li,ul:true:true,win:5' && ret === true);
        var once = 0; li.addEventListener('k', function () { once++; }, { once: true });
        li.dispatchEvent(new Event('k')); li.dispatchEvent(new Event('k'));
        ok('once', once === 1);
        var stopped = 0; ul.addEventListener('s', function () { stopped++; });
        li.addEventListener('s', function (e) { e.stopPropagation(); e.preventDefault(); });
        ok('stop + preventDefault', li.dispatchEvent(new Event('s', { bubbles: true, cancelable: true })) === false && stopped === 0);
        var clicked = 0; li.onclick = function () { clicked++; }; li.click();
        ok('click + on-handler', clicked === 1);
        var old = document.createEvent('Event'); old.initEvent('legacy', true, true);
        var got = 0; document.addEventListener('legacy', function () { got++; }); li.dispatchEvent(old);
        ok('createEvent', got === 1);
        var d2 = document.implementation.createHTMLDocument('x');
        d2.body.innerHTML = '<form></form><form></form>';
        ok('createHTMLDocument', d2 !== document && d2.body.childNodes.length === 2 && d2.title === 'x' && d2.body.firstChild.ownerDocument === d2);
        var moved = document.adoptNode(d2.body.firstChild);
        ok('adoptNode', moved.ownerDocument === document);
        ok('native-looking', /\[native code\]/.test(document.querySelectorAll + '') && /\[native code\]/.test(Element.prototype.matches + '') && !/\[native code\]/.test((function () {}) + ''));
        ok('range fragment', document.createRange().createContextualFragment('<b>x</b>').firstChild.tagName === 'B');
        "#,
    );
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn mutation_observer_records_are_delivered() {
    let (_, out) = render_opts(
        r#"<html><head><title>t</title></head><body><ul id='l'><li>1</li></ul><script>
         var seen = [];
         new MutationObserver(function (recs) { recs.forEach(function (r) { seen.push(r.type + ':' + (r.attributeName || r.addedNodes.length)); }); document.title = seen.join('|'); })
           .observe(document.getElementById('l'), { childList: true, attributes: true, subtree: true });
         document.getElementById('l').appendChild(document.createElement('li'));
         document.querySelector('li').setAttribute('x', '1');
         </script></body></html>"#,
        true,
        1000,
    );
    assert!(out.contains("<title>childList:1|attributes:x</title>"), "{out}");
}

#[test]
fn document_write_lands_where_the_script_is_and_inserted_scripts_run() {
    let (stats, out) = render_opts(
        r#"<html><body><div id='top'>top</div><div class='c'><script>document.write('<p id="w1">one</p>'); document.write('<p id="w2">two</p>');</script><span id='after'>after</span></div><script>
         var s = document.createElement('script'); s.text = 'window.__ran = (window.__ran || 0) + 1;'; document.head.appendChild(s);
         var d = document.createElement('div'); d.innerHTML = '<script>window.__inner = 1;<\/script>'; document.body.appendChild(d);
         document.getElementById('top').textContent = 'ran=' + window.__ran + ' inner=' + window.__inner + ' cur=' + (document.currentScript && document.currentScript.tagName);
         </script></body></html>"#,
        true,
        1000,
    );
    assert!(stats.page_errors.is_empty(), "{:?}", stats.page_errors);
    let w1 = out.find("id=\"w1\"").expect("w1");
    let w2 = out.find("id=\"w2\"").expect("w2");
    let after = out.find("id=\"after\"").expect("after");
    assert!(w1 < w2 && w2 < after, "{out}");
    assert!(out.contains("ran=1 inner=undefined cur=SCRIPT"), "{out}");
}

#[test]
fn without_live_dom_the_same_page_keeps_the_native_document() {
    let (_, out) = render_opts(
        "<html><body><div id='o'>x</div><script>var d = document.createElement('div'); document.getElementById('o').textContent = String(d.childNodes === undefined) + '|' + String(typeof document.implementation);</script></body></html>",
        false,
        800,
    );
    assert!(out.contains("true|undefined"), "{out}");
}

#[test]
fn platform_interfaces_a_page_names_exist() {
    let fails = check(
        "<form id='f'><input name='a' value='1'><input type='checkbox' name='b'><input type='checkbox' name='c' checked value='on'></form>",
        r#"
        var names = ['File', 'Blob', 'FileReader', 'FormData', 'AbortSignal', 'Storage', 'History', 'Location', 'Navigator',
                     'Performance', 'DOMRect', 'NamedNodeMap', 'CSSStyleDeclaration', 'MutationRecord', 'DOMImplementation'];
        ok('defined ' + names.filter(function (n) { return typeof window[n] !== 'function'; }).join(','),
           names.every(function (n) { return typeof window[n] === 'function'; }));
        class Upload extends File {}
        var u = new Upload(['ab', 'c'], 'x.txt', { type: 'text/plain' });
        ok('file', u instanceof Blob && u.size === 3 && u.name === 'x.txt' && u.type === 'text/plain' && u.slice(1).size === 2);
        var fd = new FormData(document.getElementById('f'));
        ok('formdata', fd.get('a') === '1' && fd.get('b') === null && fd.get('c') === 'on' && Array.from(fd).length === 2);
        var r = new DOMRect(1, 2, 3, 4);
        ok('rect', r.right === 4 && r.bottom === 6);
        "#,
    );
    assert!(fails.is_empty(), "{fails:#?}");
}
