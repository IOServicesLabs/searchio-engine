// Live DOM for the render pass (render option `live_dom`).
//
// The bridge's native `document` is a set of snapshots over a re-parsed HTML
// string: a created element has no childNodes, two lookups of one node give
// two objects, and there is no document.implementation. Every framework
// runtime (jQuery, React, Vue, Svelte) needs those. This file replaces
// `document` with a tree of ordinary JS objects, one per node, so identity,
// sibling/parent links and created-node subtrees behave as in a browser.
//
// Host functions it relies on (se-js bridge):
//   __seParseHTML(html, fragment) -> JSON tree (html5ever does the parsing)
//   __sePageHTML()                -> the document this eval started from
//   __seDomTick()                 -> "the DOM changed" for the settle pump
//   __seCommitHTML(html)          -> hand the final document back
// The engine calls __seLiveFlush() after the pump; it serializes the tree.
(function (g) {
  "use strict";
  if (g.__seLive || typeof g.__seParseHTML !== "function") { return; }

  var nativeDoc = g.document;
  var tick = typeof g.__seDomTick === "function" ? g.__seDomTick : function () {};
  var HTML_NS = "http://www.w3.org/1999/xhtml";
  var SVG_NS = "http://www.w3.org/2000/svg";
  var MATH_NS = "http://www.w3.org/1998/Math/MathML";
  var NS_BY_CODE = [HTML_NS, SVG_NS, MATH_NS];
  var VOID = { area: 1, base: 1, br: 1, col: 1, embed: 1, hr: 1, img: 1, input: 1, link: 1, meta: 1, param: 1, source: 1, track: 1, wbr: 1 };
  var RAW = { script: 1, style: 1, xmp: 1, iframe: 1, noembed: 1, noframes: 1, plaintext: 1, noscript: 1 };

  function report(e) {
    try {
      var list = g.__sePageErrors || (g.__sePageErrors = []);
      if (list.length < 40) { list.push(String((e && e.stack) || e).slice(0, 400)); }
    } catch (_) {}
  }
  function domEx(name, msg) {
    var e;
    try { e = new g.DOMException(msg || name, name); } catch (_) { e = new Error(msg || name); e.name = name; }
    return e;
  }

  // ── events ────────────────────────────────────────────────────────────────
  class Event {
    constructor(type, init) {
      init = init || {};
      this.type = String(type);
      this.bubbles = !!init.bubbles;
      this.cancelable = !!init.cancelable;
      this.composed = !!init.composed;
      this.defaultPrevented = false;
      this.eventPhase = 0;
      this.currentTarget = null;
      this.isTrusted = false;
      this.timeStamp = g.performance && g.performance.now ? g.performance.now() : Date.now();
      this._target = null; this._stop = false; this._stopNow = false; this._path = null;
    }
    get target() { return this._target; }
    get srcElement() { return this._target; }
    get returnValue() { return !this.defaultPrevented; }
    set returnValue(v) { if (v === false) { this.preventDefault(); } }
    get cancelBubble() { return this._stop; }
    set cancelBubble(v) { if (v) { this._stop = true; } }
    preventDefault() { if (this.cancelable) { this.defaultPrevented = true; } }
    stopPropagation() { this._stop = true; }
    stopImmediatePropagation() { this._stop = true; this._stopNow = true; }
    composedPath() { return this._path ? this._path.slice() : []; }
    initEvent(type, bubbles, cancelable) { this.type = String(type); this.bubbles = !!bubbles; this.cancelable = !!cancelable; }
  }
  Event.NONE = 0; Event.CAPTURING_PHASE = 1; Event.AT_TARGET = 2; Event.BUBBLING_PHASE = 3;
  function eventClass(name, Base, defaults) {
    var C = { [name]: class extends Base {
      constructor(type, init) {
        super(type, init);
        var k;
        for (k in defaults) { this[k] = defaults[k]; }
        if (init) { for (k in init) { if (k !== "bubbles" && k !== "cancelable" && k !== "composed") { try { this[k] = init[k]; } catch (_) {} } } }
      }
    } }[name];
    return C;
  }
  var CustomEvent = eventClass("CustomEvent", Event, { detail: null });
  CustomEvent.prototype.initCustomEvent = function (t, b, c, d) { this.initEvent(t, b, c); this.detail = d; };
  var UIEvent = eventClass("UIEvent", Event, { view: null, detail: 0 });
  UIEvent.prototype.initUIEvent = function (t, b, c) { this.initEvent(t, b, c); };
  var MOUSE = { screenX: 0, screenY: 0, clientX: 0, clientY: 0, pageX: 0, pageY: 0, offsetX: 0, offsetY: 0, button: 0, buttons: 0, ctrlKey: false, shiftKey: false, altKey: false, metaKey: false, relatedTarget: null };
  var MouseEvent = eventClass("MouseEvent", UIEvent, MOUSE);
  MouseEvent.prototype.initMouseEvent = function (t, b, c) { this.initEvent(t, b, c); };
  MouseEvent.prototype.getModifierState = function () { return false; };
  var EVENT_CLASSES = {
    Event: Event, CustomEvent: CustomEvent, UIEvent: UIEvent, MouseEvent: MouseEvent,
    PointerEvent: eventClass("PointerEvent", MouseEvent, { pointerId: 0, pointerType: "mouse", isPrimary: true, width: 1, height: 1, pressure: 0 }),
    WheelEvent: eventClass("WheelEvent", MouseEvent, { deltaX: 0, deltaY: 0, deltaZ: 0, deltaMode: 0 }),
    DragEvent: eventClass("DragEvent", MouseEvent, { dataTransfer: null }),
    KeyboardEvent: eventClass("KeyboardEvent", UIEvent, { key: "", code: "", keyCode: 0, which: 0, charCode: 0, location: 0, repeat: false, isComposing: false, ctrlKey: false, shiftKey: false, altKey: false, metaKey: false }),
    FocusEvent: eventClass("FocusEvent", UIEvent, { relatedTarget: null }),
    InputEvent: eventClass("InputEvent", UIEvent, { data: null, inputType: "", isComposing: false }),
    CompositionEvent: eventClass("CompositionEvent", UIEvent, { data: "" }),
    TouchEvent: eventClass("TouchEvent", UIEvent, { touches: [], targetTouches: [], changedTouches: [] }),
    ErrorEvent: eventClass("ErrorEvent", Event, { message: "", filename: "", lineno: 0, colno: 0, error: null }),
    MessageEvent: eventClass("MessageEvent", Event, { data: null, origin: "", lastEventId: "", source: null, ports: [] }),
    PopStateEvent: eventClass("PopStateEvent", Event, { state: null }),
    HashChangeEvent: eventClass("HashChangeEvent", Event, { oldURL: "", newURL: "" }),
    PageTransitionEvent: eventClass("PageTransitionEvent", Event, { persisted: false }),
    ProgressEvent: eventClass("ProgressEvent", Event, { lengthComputable: false, loaded: 0, total: 0 }),
    AnimationEvent: eventClass("AnimationEvent", Event, { animationName: "", elapsedTime: 0, pseudoElement: "" }),
    TransitionEvent: eventClass("TransitionEvent", Event, { propertyName: "", elapsedTime: 0, pseudoElement: "" }),
    SubmitEvent: eventClass("SubmitEvent", Event, { submitter: null }),
    StorageEvent: eventClass("StorageEvent", Event, { key: null, oldValue: null, newValue: null, url: "", storageArea: null }),
    PromiseRejectionEvent: eventClass("PromiseRejectionEvent", Event, { promise: null, reason: undefined }),
    ClipboardEvent: eventClass("ClipboardEvent", Event, { clipboardData: null }),
    BeforeUnloadEvent: eventClass("BeforeUnloadEvent", Event, {}),
  };
  EVENT_CLASSES.KeyboardEvent.prototype.getModifierState = function () { return false; };

  var winListeners = Object.create(null);
  function listenersOf(t, create) {
    if (t === g) { return winListeners; }
    return t._l || (create ? (t._l = Object.create(null)) : null);
  }
  function addListener(t, type, fn, opts) {
    if (fn === null || fn === undefined) { return; }
    type = String(type);
    var cap = typeof opts === "boolean" ? opts : !!(opts && opts.capture);
    var L = listenersOf(t, true);
    var a = L[type] || (L[type] = []);
    for (var i = 0; i < a.length; i++) { if (a[i].fn === fn && a[i].cap === cap) { return; } }
    var rec = { fn: fn, cap: cap, once: !!(opts && typeof opts === "object" && opts.once), gone: false };
    a.push(rec);
    var sig = opts && typeof opts === "object" && opts.signal;
    if (sig && typeof sig.addEventListener === "function") {
      if (sig.aborted) { removeListener(t, type, fn, cap); return; }
      sig.addEventListener("abort", function () { removeListener(t, type, fn, cap); });
    }
  }
  function removeListener(t, type, fn, opts) {
    var cap = typeof opts === "boolean" ? opts : !!(opts && opts.capture);
    var L = listenersOf(t, false);
    var a = L && L[String(type)];
    if (!a) { return; }
    for (var i = 0; i < a.length; i++) {
      if (a[i].fn === fn && a[i].cap === cap) { a[i].gone = true; a.splice(i, 1); return; }
    }
  }
  function fire(t, ev, cap, phase) {
    ev.currentTarget = t; ev.eventPhase = phase;
    if (cap !== true) {
      var h = t["on" + ev.type];
      if (typeof h === "function") {
        try { if (h.call(t, ev) === false) { ev.preventDefault(); } } catch (e) { report(e); }
        if (ev._stopNow) { return; }
      }
    }
    var L = listenersOf(t, false);
    var a = L && L[ev.type];
    if (!a || !a.length) { return; }
    a = a.slice();
    for (var i = 0; i < a.length; i++) {
      var l = a[i];
      if (l.gone || (cap !== null && l.cap !== cap)) { continue; }
      if (l.once) { removeListener(t, ev.type, l.fn, l.cap); }
      try {
        if (typeof l.fn === "function") { l.fn.call(t, ev); }
        else if (l.fn && typeof l.fn.handleEvent === "function") { l.fn.handleEvent(ev); }
      } catch (e) { report(e); }
      if (ev._stopNow) { break; }
    }
  }
  function asEvent(ev) {
    if (ev instanceof Event) { return ev; }
    var init = ev || {};
    var e2 = new Event(String(init.type), init);
    for (var k in init) { if (!(k in e2)) { try { e2[k] = init[k]; } catch (_) {} } }
    return e2;
  }
  function dispatch(target, ev) {
    ev = asEvent(ev);
    ev._target = target; ev._stop = false; ev._stopNow = false;
    var path = [target];
    if (target !== g && target instanceof Node) {
      var n = target._p || (target.nodeType === 11 && target.host) || null;
      while (n) { path.push(n); n = n._p || (n.nodeType === 11 && n.host) || null; }
      if (path[path.length - 1] === g.document && ev.type !== "load") { path.push(g); }
    }
    ev._path = path;
    var i;
    for (i = path.length - 1; i > 0; i--) { if (ev._stop) { break; } fire(path[i], ev, true, 1); }
    if (!ev._stop) { fire(path[0], ev, null, 2); }
    if (ev.bubbles) { for (i = 1; i < path.length; i++) { if (ev._stop) { break; } fire(path[i], ev, false, 3); } }
    ev.eventPhase = 0; ev.currentTarget = null;
    return !ev.defaultPrevented;
  }

  class EventTarget {
    addEventListener(type, fn, opts) { addListener(this, type, fn, opts); }
    removeEventListener(type, fn, opts) { removeListener(this, type, fn, opts); }
    dispatchEvent(ev) { return dispatch(this, ev); }
  }

  // ── collections ───────────────────────────────────────────────────────────
  class NodeList extends Array {
    static get [Symbol.species]() { return Array; }
    item(i) { return this[i] === undefined ? null : this[i]; }
  }
  class HTMLCollection extends Array {
    static get [Symbol.species]() { return Array; }
    item(i) { return this[i] === undefined ? null : this[i]; }
    namedItem(name) {
      for (var i = 0; i < this.length; i++) {
        if (this[i]._a.get("id") === name || this[i]._a.get("name") === name) { return this[i]; }
      }
      return null;
    }
  }
  function nodeList(arr) { var l = new NodeList(); for (var i = 0; i < arr.length; i++) { l.push(arr[i]); } return l; }
  function collection(arr) { var l = new HTMLCollection(); for (var i = 0; i < arr.length; i++) { l.push(arr[i]); } return l; }

  // ── mutation observers ────────────────────────────────────────────────────
  var observers = [];
  var EMPTY = [];
  function moNotify(kind, target, fields) {
    for (var i = 0; i < observers.length; i++) {
      var mo = observers[i];
      for (var j = 0; j < mo._regs.length; j++) {
        var r = mo._regs[j];
        if (!r[kind]) { continue; }
        if (r.t !== target && !(r.subtree && r.t.contains(target))) { continue; }
        if (kind === "attributes" && r.filter && r.filter.indexOf(fields.attributeName) < 0) { continue; }
        var rec = {
          type: kind, target: target, addedNodes: fields.addedNodes || EMPTY, removedNodes: fields.removedNodes || EMPTY,
          previousSibling: fields.previousSibling || null, nextSibling: fields.nextSibling || null,
          attributeName: fields.attributeName || null, attributeNamespace: null,
          oldValue: (kind === "attributes" && r.aov) || (kind === "characterData" && r.cdov) ? fields.oldValue : null,
        };
        mo._q.push(rec);
        if (!mo._sched) { mo._sched = true; g.queueMicrotask(mo._deliver); }
        break;
      }
    }
  }
  class MutationObserver {
    constructor(cb) {
      var self = this;
      this._cb = cb; this._regs = []; this._q = []; this._sched = false;
      this._deliver = function () {
        self._sched = false;
        var q = self.takeRecords();
        if (q.length) { try { self._cb.call(self, q, self); } catch (e) { report(e); } }
      };
    }
    observe(target, o) {
      o = o || {};
      var attrs = o.attributes !== undefined ? !!o.attributes : !!(o.attributeOldValue || o.attributeFilter);
      var cd = o.characterData !== undefined ? !!o.characterData : !!o.characterDataOldValue;
      if (!(o.childList || attrs || cd)) { throw new TypeError("Failed to execute 'observe' on 'MutationObserver': The options object must set at least one of 'attributes', 'characterData', or 'childList' to true."); }
      if (!(target instanceof Node)) { throw new TypeError("Failed to execute 'observe' on 'MutationObserver': parameter 1 is not of type 'Node'."); }
      this._regs = this._regs.filter(function (r) { return r.t !== target; });
      this._regs.push({ t: target, childList: !!o.childList, attributes: attrs, characterData: cd, subtree: !!o.subtree, aov: !!o.attributeOldValue, cdov: !!o.characterDataOldValue, filter: o.attributeFilter || null });
      if (observers.indexOf(this) < 0) { observers.push(this); }
    }
    disconnect() { this._regs = []; this._q = []; var i = observers.indexOf(this); if (i >= 0) { observers.splice(i, 1); } }
    takeRecords() { var q = this._q; this._q = []; return q; }
  }

  // ── custom elements ───────────────────────────────────────────────────────
  var ceByName = new Map();
  var ceByCtor = new Map();
  var ceWaiting = new Map();
  var upgradeStack = [];
  var creating = null;
  function ceCall(el, name, args) {
    var f = el[name];
    if (typeof f === "function") { try { f.apply(el, args || []); } catch (e) { report(e); } }
  }
  function ceUpgrade(el, def) {
    if (el._ce) { return; }
    el._ce = def;
    upgradeStack.push(el);
    try { new def.ctor(); } catch (e) { report(e); Object.setPrototypeOf(el, def.ctor.prototype); }
    upgradeStack.pop();
    if (def.observed.length) {
      el._a.forEach(function (v, k) { if (def.observed.indexOf(k) >= 0) { ceCall(el, "attributeChangedCallback", [k, null, v, null]); } });
    }
    if (el.isConnected) { ceCall(el, "connectedCallback"); }
  }
  var customElements = {
    define: function (name, ctor) {
      name = String(name);
      if (ceByName.has(name)) { throw domEx("NotSupportedError", "the name \"" + name + "\" has already been used with this registry"); }
      var observed = [];
      try { observed = Array.prototype.slice.call(ctor.observedAttributes || []); } catch (_) {}
      var def = { name: name, ctor: ctor, observed: observed };
      ceByName.set(name, def); ceByCtor.set(ctor, def);
      var doc = g.document;
      if (doc && doc.documentElement) {
        var hits = [];
        walk(doc, function (n) { if (n.nodeType === 1 && n._t === name) { hits.push(n); } });
        for (var i = 0; i < hits.length; i++) { ceUpgrade(hits[i], def); }
      }
      var w = ceWaiting.get(name);
      if (w) { ceWaiting.delete(name); w.forEach(function (res) { res(ctor); }); }
    },
    get: function (name) { var d = ceByName.get(String(name)); return d ? d.ctor : undefined; },
    getName: function (ctor) { var d = ceByCtor.get(ctor); return d ? d.name : null; },
    whenDefined: function (name) {
      name = String(name);
      var d = ceByName.get(name);
      if (d) { return Promise.resolve(d.ctor); }
      return new Promise(function (res) { var w = ceWaiting.get(name) || []; w.push(res); ceWaiting.set(name, w); });
    },
    upgrade: function (root) {
      walk(root, function (n) { if (n.nodeType === 1) { var d = ceByName.get(n._t); if (d) { ceUpgrade(n, d); } } });
    },
  };

  // ── nodes ─────────────────────────────────────────────────────────────────
  function walk(root, fn) {
    var c = root._c;
    if (!c) { return; }
    for (var i = 0; i < c.length; i++) {
      var n = c[i];
      if (fn(n) === false) { return false; }
      if (n._c && n._c.length && walk(n, fn) === false) { return false; }
    }
  }
  function connected(n) {
    for (;;) {
      if (n._p) { n = n._p; continue; }
      if (n.nodeType === 11 && n.host) { n = n.host; continue; }
      return n.nodeType === 9;
    }
  }
  function adopt(node, doc) {
    node._d = doc;
    if (node._c) { walk(node, function (n) { n._d = doc; }); }
  }
  var scriptBudget = 48;
  var currentScript = null;
  var NONCONTENT = /(^|\.)(google-analytics\.com|googletagmanager\.com|doubleclick\.net|googlesyndication\.com|google\.com\/recaptcha|facebook\.net|hotjar\.com|segment\.(com|io)|sentry\.io|sentry-cdn\.com|newrelic\.com|nr-data\.net|clarity\.ms|optimizely\.com|adservice\.google\.com|amazon-adsystem\.com|scorecardresearch\.com|quantserve\.com|criteo\.(com|net)|taboola\.com|outbrain\.com|datadoghq-browser-agent\.com|fullstory\.com|mixpanel\.com|amplitude\.com|intercomcdn\.com|cookielaw\.org|onetrust\.com)/i;
  function later(fn) { g.setTimeout(fn, 0); }
  function fireSimple(el, type) { try { dispatch(el, new Event(type)); } catch (e) { report(e); } }
  function runCode(el, code) {
    var prev = currentScript;
    currentScript = el;
    try { (0, eval)(code); } catch (e) { report(e); } finally { currentScript = prev; }
  }
  function runScript(el) {
    if (el._ran) { return; }
    var type = (el._a.get("type") || "").trim().toLowerCase();
    if (type && !/^(text|application)\/(x-)?(java|ecma)script$/.test(type)) {
      if (type === "module") { el._ran = true; report("module script not run: " + (el._a.get("src") || "inline")); }
      return;
    }
    var src = el._a.get("src");
    if (src === undefined || src === "") {
      if (src === "") { return; }
      var code = el.textContent;
      if (!code) { return; }
      el._ran = true;
      runCode(el, code);
      return;
    }
    el._ran = true;
    var url = resolveURL(el, src);
    if (scriptBudget-- <= 0 || NONCONTENT.test(url.replace(/^https?:\/\//, "")) || typeof g.fetch !== "function") {
      later(function () { fireSimple(el, "load"); });
      return;
    }
    g.fetch(url).then(function (r) {
      if (!r.ok) { throw new Error("script " + url + " -> " + r.status); }
      return r.text();
    }).then(function (code) {
      runCode(el, code);
      fireSimple(el, "load");
    }, function (e) { report(e); fireSimple(el, "error"); });
  }
  function onConnect(node) {
    if (node.nodeType !== 1) {
      if (node.nodeType === 11) { walk(node, function (n) { if (n.nodeType === 1) { connectOne(n); } }); }
      return;
    }
    connectOne(node);
    if (node._c.length) { walk(node, function (n) { if (n.nodeType === 1) { connectOne(n); } }); }
  }
  function connectOne(el) {
    var t = el._t;
    if (t === "script") { if (el._ns === HTML_NS) { runScript(el); } return; }
    if (t === "base") { el._d._base = undefined; return; }
    if (t === "link") {
      var rel = (el._a.get("rel") || "").toLowerCase();
      if (/stylesheet|preload|modulepreload|prefetch/.test(rel)) { later(function () { fireSimple(el, "load"); }); }
      return;
    }
    if (t === "iframe") { later(function () { fireSimple(el, "load"); }); return; }
    if (ceByName.size) {
      var def = el._ce || ceByName.get(t);
      if (def) { if (!el._ce) { ceUpgrade(el, def); } else { ceCall(el, "connectedCallback"); } }
    }
  }
  function onDisconnect(node) {
    if (!ceByName.size || node.nodeType !== 1) { return; }
    if (node._ce) { ceCall(node, "disconnectedCallback"); }
    walk(node, function (n) { if (n._ce) { ceCall(n, "disconnectedCallback"); } });
  }
  function detach(node) {
    var p = node._p;
    if (!p) { return; }
    var c = p._c, i = c.indexOf(node);
    var was = ceByName.size ? connected(p) : false;
    if (observers.length) { moNotify("childList", p, { removedNodes: [node], previousSibling: c[i - 1], nextSibling: c[i + 1] }); }
    c.splice(i, 1);
    node._p = null;
    tick();
    if (was) { onDisconnect(node); }
  }
  function insert(parent, node, ref) {
    if (!(node instanceof Node)) { throw new TypeError("Failed to execute 'appendChild' on 'Node': parameter 1 is not of type 'Node'."); }
    if (!parent._c) { throw domEx("HierarchyRequestError", "This node type does not support this method."); }
    if (ref && ref._p !== parent) { throw domEx("NotFoundError", "The node before which the new node is to be inserted is not a child of this node."); }
    if (node.nodeType === 11) {
      var kids = node._c.slice();
      for (var k = 0; k < kids.length; k++) { insert(parent, kids[k], ref); }
      return node;
    }
    if (node.nodeType === 9) { throw domEx("HierarchyRequestError", "Nodes of type '#document' may not be inserted inside nodes of type '" + parent.nodeName + "'."); }
    if (node._c && node.contains(parent)) { throw domEx("HierarchyRequestError", "The new child element contains the parent."); }
    if (node === ref) { ref = node.nextSibling; }
    if (node._p) { detach(node); }
    var c = parent._c;
    if (ref) { c.splice(c.indexOf(ref), 0, node); } else { c.push(node); }
    node._p = parent;
    var d = parent.nodeType === 9 ? parent : parent._d;
    if (node._d !== d) { adopt(node, d); }
    tick();
    if (observers.length) { var at = c.indexOf(node); moNotify("childList", parent, { addedNodes: [node], previousSibling: c[at - 1], nextSibling: c[at + 1] }); }
    if (d === g.document) {
      if (node.nodeType === 1) { if (connected(parent)) { onConnect(node); } }
      else if (parent.nodeType === 1 && parent._t === "script" && !parent._ran && connected(parent)) { runScript(parent); }
    }
    return node;
  }
  function toNode(doc, v) { return v instanceof Node ? v : doc.createTextNode(String(v)); }
  function nodesToFragment(owner, args) {
    var doc = owner.nodeType === 9 ? owner : owner._d;
    if (args.length === 1) { return toNode(doc, args[0]); }
    var f = doc.createDocumentFragment();
    for (var i = 0; i < args.length; i++) { f.appendChild(toNode(doc, args[i])); }
    return f;
  }

  class Node extends EventTarget {
    get parentNode() { return this._p || null; }
    get parentElement() { var p = this._p; return p && p.nodeType === 1 ? p : null; }
    get childNodes() { return this._c || (this._nc || (this._nc = new NodeList())); }
    get firstChild() { var c = this._c; return c && c.length ? c[0] : null; }
    get lastChild() { var c = this._c; return c && c.length ? c[c.length - 1] : null; }
    get nextSibling() { var p = this._p; if (!p) { return null; } var c = p._c; return c[c.indexOf(this) + 1] || null; }
    get previousSibling() { var p = this._p; if (!p) { return null; } var c = p._c; return c[c.indexOf(this) - 1] || null; }
    get ownerDocument() { return this.nodeType === 9 ? null : this._d; }
    get isConnected() { return connected(this); }
    get nodeValue() { return null; }
    set nodeValue(v) {}
    get baseURI() { return docBase(this.nodeType === 9 ? this : this._d); }
    getRootNode(o) {
      var n = this;
      for (;;) {
        if (n._p) { n = n._p; continue; }
        if (o && o.composed && n.nodeType === 11 && n.host) { n = n.host; continue; }
        return n;
      }
    }
    hasChildNodes() { return !!(this._c && this._c.length); }
    contains(o) { while (o) { if (o === this) { return true; } o = o._p; } return false; }
    appendChild(n) { return insert(this, n, null); }
    insertBefore(n, ref) { return insert(this, n, ref || null); }
    removeChild(n) {
      if (!n || n._p !== this) { throw domEx("NotFoundError", "The node to be removed is not a child of this node."); }
      detach(n);
      return n;
    }
    replaceChild(n, old) {
      if (!old || old._p !== this) { throw domEx("NotFoundError", "The node to be replaced is not a child of this node."); }
      if (n === old) { return old; }
      var next = old.nextSibling;
      if (next === n) { next = n.nextSibling; }
      detach(old);
      insert(this, n, next);
      return old;
    }
    cloneNode(deep) { return this._clone(!!deep, this.nodeType === 9 ? this : this._d); }
    get textContent() { return null; }
    set textContent(v) {}
    normalize() {
      var c = this._c;
      if (!c) { return; }
      for (var i = 0; i < c.length; i++) {
        var n = c[i];
        if (n.nodeType === 3) {
          if (!n._v) { detach(n); i--; continue; }
          while (c[i + 1] && c[i + 1].nodeType === 3) { n._v += c[i + 1]._v; detach(c[i + 1]); }
        } else if (n._c) { n.normalize(); }
      }
    }
    isSameNode(o) { return o === this; }
    isEqualNode(o) {
      if (!o || o.nodeType !== this.nodeType || o.nodeName !== this.nodeName) { return false; }
      if (this.nodeType === 1) { return this.outerHTML === o.outerHTML; }
      if (this._c) { return serializeChildren(this) === serializeChildren(o); }
      return this._v === o._v;
    }
    compareDocumentPosition(o) {
      if (o === this) { return 0; }
      var a = [], b = [], n;
      for (n = this; n; n = n._p) { a.unshift(n); }
      for (n = o; n; n = n._p) { b.unshift(n); }
      if (a[0] !== b[0]) { return 1 | 32 | 4; }
      var i = 0;
      while (i < a.length && i < b.length && a[i] === b[i]) { i++; }
      if (i === a.length) { return 16 | 4; }
      if (i === b.length) { return 8 | 2; }
      var sibs = a[i - 1]._c;
      return sibs.indexOf(a[i]) < sibs.indexOf(b[i]) ? 4 : 2;
    }
    lookupNamespaceURI() { return null; }
    lookupPrefix() { return null; }
    isDefaultNamespace(ns) { return ns === HTML_NS; }
  }
  var NODE_CONSTS = { ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3, CDATA_SECTION_NODE: 4, PROCESSING_INSTRUCTION_NODE: 7, COMMENT_NODE: 8, DOCUMENT_NODE: 9, DOCUMENT_TYPE_NODE: 10, DOCUMENT_FRAGMENT_NODE: 11, DOCUMENT_POSITION_DISCONNECTED: 1, DOCUMENT_POSITION_PRECEDING: 2, DOCUMENT_POSITION_FOLLOWING: 4, DOCUMENT_POSITION_CONTAINS: 8, DOCUMENT_POSITION_CONTAINED_BY: 16, DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC: 32 };
  Object.keys(NODE_CONSTS).forEach(function (k) { Node[k] = NODE_CONSTS[k]; Node.prototype[k] = NODE_CONSTS[k]; });

  // ChildNode / ParentNode mixins
  var ChildNode = {
    before: function () { var p = this._p; if (p) { insert(p, nodesToFragment(this, arguments), this); } },
    after: function () { var p = this._p; if (p) { var next = this.nextSibling; insert(p, nodesToFragment(this, arguments), next); } },
    replaceWith: function () { var p = this._p; if (p) { var next = this.nextSibling; var f = nodesToFragment(this, arguments); if (f === this) { return; } detach(this); insert(p, f, next && next._p === p ? next : null); } },
    remove: function () { detach(this); },
  };
  function elementChildren(n) { var out = [], c = n._c; for (var i = 0; i < c.length; i++) { if (c[i].nodeType === 1) { out.push(c[i]); } } return out; }
  var ParentNode = {
    append: function () { insert(this, nodesToFragment(this, arguments), null); },
    prepend: function () { insert(this, nodesToFragment(this, arguments), this._c[0] || null); },
    replaceChildren: function () { clearChildren(this); if (arguments.length) { insert(this, nodesToFragment(this, arguments), null); } },
    querySelector: function (sel) { return select(this, sel, true); },
    querySelectorAll: function (sel) { return nodeList(select(this, sel, false)); },
    getElementsByTagName: function (name) {
      name = String(name);
      var out = [], any = name === "*", lower = name.toLowerCase();
      walk(this, function (n) { if (n.nodeType === 1 && (any || n._t === lower || n._t === name)) { out.push(n); } });
      return collection(out);
    },
    getElementsByTagNameNS: function (ns, name) { return this.getElementsByTagName(name); },
    getElementsByClassName: function (names) {
      var want = String(names).split(/\s+/).filter(Boolean), out = [];
      if (!want.length) { return collection(out); }
      walk(this, function (n) {
        if (n.nodeType !== 1) { return; }
        var cls = n._a.get("class");
        if (!cls) { return; }
        var have = " " + cls.replace(/[\t\n\f\r]/g, " ") + " ";
        for (var i = 0; i < want.length; i++) { if (have.indexOf(" " + want[i] + " ") < 0) { return; } }
        out.push(n);
      });
      return collection(out);
    },
  };
  var ParentNodeGetters = {
    children: function () { return collection(elementChildren(this)); },
    firstElementChild: function () { var c = this._c; for (var i = 0; i < c.length; i++) { if (c[i].nodeType === 1) { return c[i]; } } return null; },
    lastElementChild: function () { var c = this._c; for (var i = c.length - 1; i >= 0; i--) { if (c[i].nodeType === 1) { return c[i]; } } return null; },
    childElementCount: function () { return elementChildren(this).length; },
  };
  function mixin(C, methods, getters) {
    var k;
    for (k in methods) { Object.defineProperty(C.prototype, k, { value: methods[k], writable: true, configurable: true }); }
    for (k in (getters || {})) { Object.defineProperty(C.prototype, k, { get: getters[k], configurable: true }); }
  }
  function clearChildren(n) {
    var c = n._c;
    while (c.length) { detach(c[c.length - 1]); }
  }
  function textOf(n, out) {
    var c = n._c;
    for (var i = 0; i < c.length; i++) {
      var k = c[i];
      if (k.nodeType === 3) { out.push(k._v); } else if (k.nodeType === 1 || k.nodeType === 11) { textOf(k, out); }
    }
  }
  function setText(n, v) {
    clearChildren(n);
    v = v === null || v === undefined ? "" : String(v);
    if (v) { insert(n, (n.nodeType === 9 ? n : n._d).createTextNode(v), null); }
  }

  class CharacterData extends Node {
    constructor(doc, v) { super(); this._p = null; this._d = doc; this._v = v; }
    get data() { return this._v; }
    set data(v) {
      v = v === null ? "" : String(v);
      var old = this._v;
      if (old === v) { return; }
      this._v = v;
      tick();
      if (observers.length) { moNotify("characterData", this, { oldValue: old }); }
    }
    get nodeValue() { return this._v; }
    set nodeValue(v) { this.data = v; }
    get textContent() { return this._v; }
    set textContent(v) { this.data = v; }
    get length() { return this._v.length; }
    appendData(s) { this.data = this._v + s; }
    insertData(o, s) { this.data = this._v.slice(0, o) + s + this._v.slice(o); }
    deleteData(o, n) { this.data = this._v.slice(0, o) + this._v.slice(o + n); }
    replaceData(o, n, s) { this.data = this._v.slice(0, o) + s + this._v.slice(o + n); }
    substringData(o, n) { return this._v.substr(o, n); }
    get nextElementSibling() { return siblingElement(this, 1); }
    get previousElementSibling() { return siblingElement(this, -1); }
  }
  mixin(CharacterData, ChildNode);
  function siblingElement(n, dir) {
    var p = n._p;
    if (!p) { return null; }
    var c = p._c;
    for (var i = c.indexOf(n) + dir; i >= 0 && i < c.length; i += dir) { if (c[i].nodeType === 1) { return c[i]; } }
    return null;
  }
  class Text extends CharacterData {
    constructor(v) { if (creating && creating.text) { var d = creating.doc; creating = null; super(d, v); } else { super(g.document, v === undefined ? "" : String(v)); } }
    get nodeType() { return 3; }
    get nodeName() { return "#text"; }
    get wholeText() { return this._v; }
    splitText(o) {
      var rest = this._d.createTextNode(this._v.slice(o));
      this.data = this._v.slice(0, o);
      if (this._p) { insert(this._p, rest, this.nextSibling); }
      return rest;
    }
    _clone(deep, doc) { return doc.createTextNode(this._v); }
  }
  class Comment extends CharacterData {
    constructor(v) { if (creating && creating.text) { var d = creating.doc; creating = null; super(d, v); } else { super(g.document, v === undefined ? "" : String(v)); } }
    get nodeType() { return 8; }
    get nodeName() { return "#comment"; }
    _clone(deep, doc) { return doc.createComment(this._v); }
  }
  class DocumentType extends Node {
    constructor(doc, name, pub, sys) { super(); this._p = null; this._d = doc; this.name = name; this.publicId = pub || ""; this.systemId = sys || ""; }
    get nodeType() { return 10; }
    get nodeName() { return this.name; }
    _clone(deep, doc) { return new DocumentType(doc, this.name, this.publicId, this.systemId); }
  }
  mixin(DocumentType, ChildNode);

  class DocumentFragment extends Node {
    constructor() {
      super();
      var d = creating && creating.frag ? creating.doc : g.document;
      creating = null;
      this._p = null; this._d = d; this._c = new NodeList();
    }
    get nodeType() { return 11; }
    get nodeName() { return "#document-fragment"; }
    get textContent() { var out = []; textOf(this, out); return out.join(""); }
    set textContent(v) { setText(this, v); }
    getElementById(id) { return byId(this, id); }
    _clone(deep, doc) {
      var f = doc.createDocumentFragment();
      if (deep) { for (var i = 0; i < this._c.length; i++) { f._c.push(adoptClone(this._c[i]._clone(true, doc), f)); } }
      return f;
    }
  }
  mixin(DocumentFragment, ParentNode, ParentNodeGetters);
  function adoptClone(n, parent) { n._p = parent; return n; }
  class ShadowRoot extends DocumentFragment {
    get innerHTML() { return serializeChildren(this); }
    set innerHTML(html) { setInner(this, html, this.host); }
    get activeElement() { return null; }
  }
  function byId(root, id) {
    id = String(id);
    var hit = null;
    walk(root, function (n) { if (n.nodeType === 1 && n._a.get("id") === id) { hit = n; return false; } });
    return hit;
  }

  // ── serialization ─────────────────────────────────────────────────────────
  function escText(s) { return s.replace(/[&<> ]/g, function (c) { return c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&nbsp;"; }); }
  function escAttr(s) { return s.replace(/[&" ]/g, function (c) { return c === "&" ? "&amp;" : c === "\"" ? "&quot;" : "&nbsp;"; }); }
  function serialize(n, out) {
    switch (n.nodeType) {
      case 1: {
        var t = n._t;
        out.push("<", t);
        n._a.forEach(function (v, k) { out.push(" ", k, "=\"", escAttr(v), "\""); });
        out.push(">");
        if (n._ns === HTML_NS && VOID[t] === 1) { return; }
        if (n._shadow) { serializeInto(n._shadow, out, false); }
        serializeInto(t === "template" && n._content ? n._content : n, out, n._ns === HTML_NS && RAW[t] === 1);
        out.push("</", t, ">");
        return;
      }
      case 3: out.push(escText(n._v)); return;
      case 8: out.push("<!--", n._v, "-->"); return;
      case 10: out.push("<!DOCTYPE ", n.name, ">"); return;
      case 9: case 11: serializeInto(n, out, false); return;
    }
  }
  function serializeInto(n, out, raw) {
    var c = n._c;
    for (var i = 0; i < c.length; i++) {
      if (raw && c[i].nodeType === 3) { out.push(c[i]._v); } else { serialize(c[i], out); }
    }
  }
  function serializeChildren(n) { var out = []; serializeInto(n.nodeType === 1 && n._t === "template" && n._content ? n._content : n, out, n.nodeType === 1 && n._ns === HTML_NS && RAW[n._t] === 1); return out.join(""); }

  // ── building from the parser's JSON tree ──────────────────────────────────
  function buildInto(doc, parent, arr, parsed) {
    for (var i = 0; i < arr.length; i++) {
      var e = arr[i], n;
      switch (e[0]) {
        case 1: {
          n = makeElement(doc, e[1], NS_BY_CODE[e[4] || 0]);
          var at = e[2];
          for (var j = 0; j < at.length; j += 2) { n._a.set(at[j], at[j + 1]); }
          if (parsed && e[1] === "script") { n._ran = true; }
          var into = n;
          if (e[1] === "template" && n._content) { into = n._content; }
          if (e[3].length) { buildInto(doc, into, e[3], parsed); }
          break;
        }
        case 3: n = doc.createTextNode(e[1]); break;
        case 8: n = doc.createComment(e[1]); break;
        case 10: n = new DocumentType(doc, e[1], e[2], e[3]); break;
        default: continue;
      }
      n._p = parent;
      parent._c.push(n);
    }
  }
  function parseFragment(doc, html, context, runnable) {
    var f = doc.createDocumentFragment();
    html = html === null || html === undefined ? "" : String(html);
    if (!html) { return f; }
    if (context && context.nodeType === 1 && context._ns === HTML_NS && RAW[context._t] === 1 && context._t !== "noscript") {
      f._c.push(adoptClone(doc.createTextNode(html), f));
      return f;
    }
    if (html.indexOf("<") < 0 && html.indexOf("&") < 0) {
      f._c.push(adoptClone(doc.createTextNode(html), f));
      return f;
    }
    var tree;
    try { tree = JSON.parse(g.__seParseHTML(html, true)); } catch (e) { report(e); tree = []; }
    buildInto(doc, f, tree, !runnable);
    return f;
  }
  function setInner(n, html, context) {
    var target = n.nodeType === 1 && n._t === "template" && n._content ? n._content : n;
    clearChildren(target);
    var f = parseFragment(n.nodeType === 9 ? n : n._d, html, context || n);
    if (f._c.length) { insert(target, f, null); }
  }

  // ── selectors ─────────────────────────────────────────────────────────────
  var selCache = new Map();
  function synErr(sel) { return domEx("SyntaxError", "'" + sel + "' is not a valid selector."); }
  var IDENT = /^(?:\\[0-9a-fA-F]{1,6}\s?|\\[^\n]|[\w-]|[^\x00-\x7f])+/;
  function unesc(s) {
    return s.indexOf("\\") < 0 ? s : s.replace(/\\([0-9a-fA-F]{1,6})\s?|\\([^\n])/g, function (m, hex, ch) { return hex ? String.fromCodePoint(parseInt(hex, 16)) : ch; });
  }
  var PSEUDO_ARGS = { not: 1, is: 1, where: 1, matches: 1, has: 1, "nth-child": 2, "nth-last-child": 2, "nth-of-type": 2, "nth-last-of-type": 2, lang: 3, dir: 3 };
  var PSEUDO_PLAIN = { "first-child": 1, "last-child": 1, "only-child": 1, "first-of-type": 1, "last-of-type": 1, "only-of-type": 1, empty: 1, root: 1, scope: 1, checked: 1, disabled: 1, enabled: 1, link: 1, "any-link": 1, hover: 1, focus: 1, active: 1, visited: 1, target: 1, "focus-within": 1, "focus-visible": 1, required: 1, optional: 1, "read-only": 1, "read-write": 1, defined: 1, indeterminate: 1, "placeholder-shown": 1, valid: 1, invalid: 1, default: 1 };
  function parseNth(arg, sel) {
    arg = arg.trim().toLowerCase();
    if (arg === "odd") { return [2, 1]; }
    if (arg === "even") { return [2, 0]; }
    var m = /^([+-]?\d+)$/.exec(arg);
    if (m) { return [0, parseInt(m[1], 10)]; }
    m = /^([+-]?\d*)n(?:\s*([+-])\s*(\d+))?$/.exec(arg);
    if (!m) { throw synErr(sel); }
    var a = m[1] === "" || m[1] === "+" ? 1 : m[1] === "-" ? -1 : parseInt(m[1], 10);
    var b = m[2] ? (m[2] === "-" ? -1 : 1) * parseInt(m[3], 10) : 0;
    return [a, b];
  }
  function parseList(sel, relative) {
    var s = sel, i = 0, n = s.length;
    function ws() { var had = false; while (i < n && /\s/.test(s[i])) { i++; had = true; } return had; }
    function ident() {
      var m = IDENT.exec(s.slice(i));
      if (!m) { throw synErr(sel); }
      i += m[0].length;
      return unesc(m[0]);
    }
    function balanced() {
      var depth = 1, start = i, q = null;
      for (; i < n; i++) {
        var c = s[i];
        if (q) { if (c === "\\") { i++; } else if (c === q) { q = null; } continue; }
        if (c === "\"" || c === "'") { q = c; } else if (c === "(") { depth++; } else if (c === ")") { if (--depth === 0) { var out = s.slice(start, i); i++; return out; } }
      }
      throw synErr(sel);
    }
    function compound() {
      var c = { tag: null, tagL: null, id: null, classes: null, attrs: null, pseudos: null }, any = false;
      if (s[i] === "*") { i++; c.tag = "*"; any = true; }
      else if (i < n && IDENT.test(s[i]) && !/[#.:\[]/.test(s[i])) { c.tag = ident(); c.tagL = c.tag.toLowerCase(); any = true; }
      for (;;) {
        var ch = s[i];
        if (ch === "#") { i++; c.id = ident(); any = true; }
        else if (ch === ".") { i++; (c.classes || (c.classes = [])).push(ident()); any = true; }
        else if (ch === "[") {
          i++; ws();
          var name = ident(); ws();
          var a = { name: name, nameL: name.toLowerCase(), op: null, val: null, ci: false };
          if (s[i] !== "]") {
            var m = /^(?:[~|^$*]?=)/.exec(s.slice(i, i + 2));
            if (!m) { throw synErr(sel); }
            a.op = m[0]; i += m[0].length; ws();
            if (s[i] === "\"" || s[i] === "'") {
              var q = s[i], st = ++i;
              while (i < n && s[i] !== q) { if (s[i] === "\\") { i++; } i++; }
              if (i >= n) { throw synErr(sel); }
              a.val = unesc(s.slice(st, i)); i++;
            } else { a.val = ident(); }
            ws();
            if (s[i] === "i" || s[i] === "I") { a.ci = true; i++; ws(); } else if (s[i] === "s" || s[i] === "S") { i++; ws(); }
          }
          if (s[i] !== "]") { throw synErr(sel); }
          i++;
          (c.attrs || (c.attrs = [])).push(a); any = true;
        }
        else if (ch === ":") {
          i++;
          if (s[i] === ":") { throw synErr(sel); }
          var pn = ident().toLowerCase(), p = { name: pn, arg: null };
          if (s[i] === "(") {
            i++;
            var raw = balanced();
            var kind = PSEUDO_ARGS[pn];
            if (!kind) { throw synErr(sel); }
            if (kind === 1) { p.arg = parseList(raw, pn === "has"); }
            else if (kind === 2) { p.arg = parseNth(raw, sel); }
            else { p.arg = raw; }
          } else if (!PSEUDO_PLAIN[pn]) { throw synErr(sel); }
          (c.pseudos || (c.pseudos = [])).push(p); any = true;
        }
        else { break; }
      }
      if (!any) { throw synErr(sel); }
      return c;
    }
    var list = [];
    ws();
    if (i >= n) { throw synErr(sel); }
    for (;;) {
      var parts = [], comb = " ";
      if (relative && /[>+~]/.test(s[i] || "")) { comb = s[i]; i++; ws(); }
      var lead = comb;
      for (;;) {
        parts.push({ comb: comb, cmp: compound() });
        var had = ws();
        var ch = s[i];
        if (ch === ">" || ch === "+" || ch === "~") { comb = ch; i++; ws(); }
        else if (had && i < n && ch !== ",") { comb = " "; }
        else { break; }
      }
      list.push({ parts: parts, lead: lead });
      if (s[i] === ",") { i++; ws(); if (i >= n) { throw synErr(sel); } continue; }
      break;
    }
    if (i < n) { throw synErr(sel); }
    return list;
  }
  function compile(sel) {
    sel = String(sel);
    var hit = selCache.get(sel);
    if (hit) { return hit; }
    hit = parseList(sel, false);
    if (selCache.size > 600) { selCache.clear(); }
    selCache.set(sel, hit);
    return hit;
  }
  function prevEl(el) { return siblingElement(el, -1); }
  function nthIndex(el, fromEnd, ofType) {
    var p = el._p;
    if (!p) { return 1; }
    var c = p._c, idx = 0, i;
    if (fromEnd) { for (i = c.length - 1; i >= 0; i--) { if (c[i].nodeType === 1 && (!ofType || c[i]._t === el._t)) { idx++; if (c[i] === el) { break; } } } }
    else { for (i = 0; i < c.length; i++) { if (c[i].nodeType === 1 && (!ofType || c[i]._t === el._t)) { idx++; if (c[i] === el) { break; } } } }
    return idx;
  }
  function nthOk(ab, idx) {
    var a = ab[0], b = ab[1];
    if (a === 0) { return idx === b; }
    var k = (idx - b) / a;
    return k >= 0 && k === Math.floor(k);
  }
  var FORMISH = { input: 1, select: 1, textarea: 1, button: 1, option: 1, optgroup: 1, fieldset: 1 };
  function matchPseudo(el, p, scope) {
    switch (p.name) {
      case "not": return !matchAny(el, p.arg, scope);
      case "is": case "where": case "matches": return matchAny(el, p.arg, scope);
      case "has": {
        var found = false;
        for (var li = 0; li < p.arg.length && !found; li++) {
          var cx = p.arg[li];
          if (cx.lead === ">") {
            var kids = el._c;
            for (var k = 0; k < kids.length; k++) { if (kids[k].nodeType === 1 && matchComplex(kids[k], cx.parts, cx.parts.length - 1, el)) { found = true; break; } }
          } else if (cx.lead === "+" || cx.lead === "~") {
            for (var sib = siblingElement(el, 1); sib; sib = siblingElement(sib, 1)) {
              if (matchComplex(sib, cx.parts, cx.parts.length - 1, el)) { found = true; break; }
              if (cx.lead === "+") { break; }
            }
          } else {
            walk(el, function (d) { if (d.nodeType === 1 && matchComplex(d, cx.parts, cx.parts.length - 1, el)) { found = true; return false; } });
          }
        }
        return found;
      }
      case "first-child": return nthIndex(el, false, false) === 1;
      case "last-child": return nthIndex(el, true, false) === 1;
      case "only-child": return nthIndex(el, false, false) === 1 && nthIndex(el, true, false) === 1;
      case "first-of-type": return nthIndex(el, false, true) === 1;
      case "last-of-type": return nthIndex(el, true, true) === 1;
      case "only-of-type": return nthIndex(el, false, true) === 1 && nthIndex(el, true, true) === 1;
      case "nth-child": return nthOk(p.arg, nthIndex(el, false, false));
      case "nth-last-child": return nthOk(p.arg, nthIndex(el, true, false));
      case "nth-of-type": return nthOk(p.arg, nthIndex(el, false, true));
      case "nth-last-of-type": return nthOk(p.arg, nthIndex(el, true, true));
      case "empty": { var c = el._c; for (var i = 0; i < c.length; i++) { if (c[i].nodeType === 1 || (c[i].nodeType === 3 && c[i]._v)) { return false; } } return true; }
      case "root": return !!el._p && el._p.nodeType === 9;
      case "scope": return scope ? el === scope : (!!el._p && el._p.nodeType === 9);
      case "checked": return (el._t === "option" ? el.selected : (el._t === "input" && el.checked)) === true;
      case "disabled": return FORMISH[el._t] === 1 && el._a.has("disabled");
      case "enabled": return FORMISH[el._t] === 1 && !el._a.has("disabled");
      case "link": case "any-link": return (el._t === "a" || el._t === "area") && el._a.has("href");
      case "required": return el._a.has("required");
      case "optional": return FORMISH[el._t] === 1 && !el._a.has("required");
      case "read-only": return !((el._t === "input" || el._t === "textarea") && !el._a.has("readonly") && !el._a.has("disabled"));
      case "read-write": return (el._t === "input" || el._t === "textarea") && !el._a.has("readonly") && !el._a.has("disabled");
      case "defined": return el._t.indexOf("-") < 0 || !!el._ce;
      case "focus": return el._d && el._d._active === el;
      case "focus-within": return !!(el._d && el._d._active && el.contains(el._d._active));
      case "valid": return FORMISH[el._t] === 1 || el._t === "form";
      default: return false;
    }
  }
  function matchAttr(el, a) {
    var v = el._a.get(el._ns === HTML_NS ? a.nameL : a.name);
    if (v === undefined) { return false; }
    if (a.op === null) { return true; }
    var want = a.val;
    if (a.ci) { v = v.toLowerCase(); want = want.toLowerCase(); }
    switch (a.op) {
      case "=": return v === want;
      case "~=": return want !== "" && !/\s/.test(want) && (" " + v.replace(/[\t\n\f\r]/g, " ") + " ").indexOf(" " + want + " ") >= 0;
      case "|=": return v === want || v.slice(0, want.length + 1) === want + "-";
      case "^=": return want !== "" && v.slice(0, want.length) === want;
      case "$=": return want !== "" && v.slice(-want.length) === want;
      case "*=": return want !== "" && v.indexOf(want) >= 0;
    }
    return false;
  }
  function matchCompound(el, c, scope) {
    var i;
    if (c.tag !== null && c.tag !== "*") {
      if (el._ns === HTML_NS ? el._t !== c.tagL : (el._t !== c.tag && el._t.toLowerCase() !== c.tagL)) { return false; }
    }
    if (c.id !== null && el._a.get("id") !== c.id) { return false; }
    if (c.classes) {
      var cls = el._a.get("class");
      if (!cls) { return false; }
      var have = " " + cls.replace(/[\t\n\f\r]/g, " ") + " ";
      for (i = 0; i < c.classes.length; i++) { if (have.indexOf(" " + c.classes[i] + " ") < 0) { return false; } }
    }
    if (c.attrs) { for (i = 0; i < c.attrs.length; i++) { if (!matchAttr(el, c.attrs[i])) { return false; } } }
    if (c.pseudos) { for (i = 0; i < c.pseudos.length; i++) { if (!matchPseudo(el, c.pseudos[i], scope)) { return false; } } }
    return true;
  }
  function matchComplex(el, parts, idx, scope) {
    if (!matchCompound(el, parts[idx].cmp, scope)) { return false; }
    if (idx === 0) { return true; }
    var p, s;
    switch (parts[idx].comb) {
      case " ": for (p = el._p; p && p.nodeType === 1; p = p._p) { if (matchComplex(p, parts, idx - 1, scope)) { return true; } } return false;
      case ">": p = el._p; return !!p && p.nodeType === 1 && matchComplex(p, parts, idx - 1, scope);
      case "+": s = prevEl(el); return !!s && matchComplex(s, parts, idx - 1, scope);
      case "~": for (s = prevEl(el); s; s = prevEl(s)) { if (matchComplex(s, parts, idx - 1, scope)) { return true; } } return false;
    }
    return false;
  }
  function matchAny(el, list, scope) {
    for (var i = 0; i < list.length; i++) { if (matchComplex(el, list[i].parts, list[i].parts.length - 1, scope)) { return true; } }
    return false;
  }
  function select(root, sel, first) {
    var list = compile(sel), out = [];
    var scope = root.nodeType === 1 ? root : null;
    walk(root, function (n) {
      if (n.nodeType === 1 && matchAny(n, list, scope)) { out.push(n); if (first) { return false; } }
    });
    return first ? (out[0] || null) : out;
  }

  // ── URLs ──────────────────────────────────────────────────────────────────
  function docBase(doc) {
    var here = doc === g.document ? String(g.location.href) : "about:blank";
    if (!doc) { return here; }
    if (doc._base === undefined || doc._baseAt !== here) {
      var b = doc._c ? select(doc, "base[href]", true) : null, out = here;
      if (b) { try { out = new g.URL(b._a.get("href"), here).href; } catch (_) {} }
      doc._base = out; doc._baseAt = here;
    }
    return doc._base;
  }
  function resolveURL(el, v) {
    try { return new g.URL(v, docBase(el._d)).href; } catch (_) { return v; }
  }

  // ── style, classList, dataset ─────────────────────────────────────────────
  function kebab(s) { return s === "cssFloat" ? "float" : s.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }).replace(/^(webkit|moz|ms|o)-/, "-$1-"); }
  function parseStyle(text) {
    var m = new Map();
    if (!text) { return m; }
    var parts = text.split(";");
    for (var i = 0; i < parts.length; i++) {
      var at = parts[i].indexOf(":");
      if (at < 0) { continue; }
      var k = parts[i].slice(0, at).trim(), v = parts[i].slice(at + 1).trim();
      if (k && v) { m.set(k.indexOf("--") === 0 ? k : k.toLowerCase(), v); }
    }
    return m;
  }
  function styleText(m) { var out = []; m.forEach(function (v, k) { out.push(k + ": " + v + ";"); }); return out.join(" "); }
  var STYLE_METHODS = {
    getPropertyValue: function (el) { return function (name) { var v = parseStyle(el._a.get("style")).get(String(name)); return v === undefined ? "" : v.replace(/\s*!important$/, ""); }; },
    getPropertyPriority: function (el) { return function (name) { var v = parseStyle(el._a.get("style")).get(String(name)); return v && /!important$/.test(v) ? "important" : ""; }; },
    setProperty: function (el) { return function (name, value, prio) { styleSet(el, String(name), value === null || value === undefined ? "" : String(value) + (prio ? " !important" : "")); }; },
    removeProperty: function (el) { return function (name) { var old = parseStyle(el._a.get("style")).get(String(name)) || ""; styleSet(el, String(name), ""); return old; }; },
    item: function (el) { return function (i) { return Array.from(parseStyle(el._a.get("style")).keys())[i] || ""; }; },
  };
  function styleSet(el, prop, value) {
    var m = parseStyle(el._a.get("style"));
    if (value === "" || value === null || value === undefined) { if (!m.has(prop)) { return; } m.delete(prop); } else { m.set(prop, String(value)); }
    var text = styleText(m);
    if (text) { setAttr(el, "style", text); } else if (el._a.has("style")) { removeAttr(el, "style"); }
  }
  function styleOf(el) {
    if (el._style) { return el._style; }
    el._style = new Proxy({}, {
      get: function (t, k) {
        if (typeof k !== "string") { return undefined; }
        if (STYLE_METHODS[k]) { return STYLE_METHODS[k](el); }
        if (k === "cssText") { return el._a.get("style") || ""; }
        if (k === "length") { return parseStyle(el._a.get("style")).size; }
        if (k === "parentRule") { return null; }
        var v = parseStyle(el._a.get("style")).get(kebab(k));
        return v === undefined ? "" : v;
      },
      set: function (t, k, v) {
        if (typeof k !== "string") { return true; }
        if (k === "cssText") { v = v === null || v === undefined ? "" : String(v); if (v) { setAttr(el, "style", v); } else { removeAttr(el, "style"); } return true; }
        styleSet(el, kebab(k), v === null || v === undefined ? "" : String(v));
        return true;
      },
      has: function (t, k) { return typeof k === "string"; },
      ownKeys: function () { return Array.from(parseStyle(el._a.get("style")).keys()); },
      getOwnPropertyDescriptor: function (t, k) { return { enumerable: true, configurable: true, writable: true, value: parseStyle(el._a.get("style")).get(k) || "" }; },
    });
    return el._style;
  }
  class DOMTokenList {
    constructor(el, attr) { this._el = el; this._attr = attr; }
    _get() { var v = this._el._a.get(this._attr); return v ? v.split(/\s+/).filter(Boolean) : []; }
    _put(list) { setAttr(this._el, this._attr, list.join(" ")); }
    get length() { return this._get().length; }
    get value() { return this._el._a.get(this._attr) || ""; }
    set value(v) { setAttr(this._el, this._attr, String(v)); }
    item(i) { var l = this._get(); return i < l.length ? l[i] : null; }
    contains(t) { return this._get().indexOf(String(t)) >= 0; }
    add() { var l = this._get(), n = l.length; for (var i = 0; i < arguments.length; i++) { var t = String(arguments[i]); if (t && l.indexOf(t) < 0) { l.push(t); } } if (l.length !== n || !this._el._a.has(this._attr)) { this._put(l); } }
    remove() { var l = this._get(), n = l.length; for (var i = 0; i < arguments.length; i++) { var at = l.indexOf(String(arguments[i])); if (at >= 0) { l.splice(at, 1); } } if (l.length !== n) { this._put(l); } }
    toggle(t, force) {
      t = String(t);
      var l = this._get(), at = l.indexOf(t);
      if (at >= 0) { if (force === true) { return true; } l.splice(at, 1); this._put(l); return false; }
      if (force === false) { return false; }
      l.push(t); this._put(l); return true;
    }
    replace(a, b) { var l = this._get(), at = l.indexOf(String(a)); if (at < 0) { return false; } l[at] = String(b); this._put(l); return true; }
    supports() { return true; }
    forEach(fn, self) { this._get().forEach(function (v, i) { fn.call(self, v, i, this); }, this); }
    keys() { return this._get().keys(); }
    values() { return this._get().values(); }
    entries() { return this._get().entries(); }
    [Symbol.iterator]() { return this._get()[Symbol.iterator](); }
    toString() { return this.value; }
  }
  function datasetOf(el) {
    if (el._ds) { return el._ds; }
    function attrName(k) { return "data-" + k.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }); }
    function propName(a) { return a.slice(5).replace(/-([a-z])/g, function (m, c) { return c.toUpperCase(); }); }
    el._ds = new Proxy({}, {
      get: function (t, k) { return typeof k === "string" ? el._a.get(attrName(k)) : undefined; },
      set: function (t, k, v) { setAttr(el, attrName(k), String(v)); return true; },
      has: function (t, k) { return typeof k === "string" && el._a.has(attrName(k)); },
      deleteProperty: function (t, k) { removeAttr(el, attrName(k)); return true; },
      ownKeys: function () { var out = []; el._a.forEach(function (v, a) { if (a.indexOf("data-") === 0) { out.push(propName(a)); } }); return out; },
      getOwnPropertyDescriptor: function (t, k) { var v = el._a.get(attrName(k)); return v === undefined ? undefined : { enumerable: true, configurable: true, writable: true, value: v }; },
    });
    return el._ds;
  }

  // ── attributes ────────────────────────────────────────────────────────────
  function attrHook(el, name, old, value) {
    tick();
    if (observers.length) { moNotify("attributes", el, { attributeName: name, oldValue: old === undefined ? null : old }); }
    if (el._ce && el._ce.observed.indexOf(name) >= 0) { ceCall(el, "attributeChangedCallback", [name, old === undefined ? null : old, value, null]); }
    if (name === "src" && value !== null && el._ns === HTML_NS) {
      if (el._t === "img") { later(function () { fireSimple(el, "load"); }); }
      else if (el._t === "script" && !el._ran && el._d === g.document && connected(el)) { runScript(el); }
    }
  }
  function setAttr(el, name, value) {
    var old = el._a.get(name);
    el._a.set(name, value);
    attrHook(el, name, old, value);
  }
  function removeAttr(el, name) {
    var old = el._a.get(name);
    if (old === undefined) { return; }
    el._a.delete(name);
    attrHook(el, name, old, null);
  }
  function attrObj(el, name, value) {
    return { name: name, localName: name, nodeName: name, value: value, nodeValue: value, textContent: value, specified: true, ownerElement: el, nodeType: 2, namespaceURI: null, prefix: null };
  }

  var ZERO_RECT = function () { return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, toJSON: function () { return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; } }; };

  class Element extends Node {
    constructor() {
      super();
      var init = creating;
      creating = null;
      if (!init || !init.el) {
        var def = ceByCtor.get(new.target);
        if (!def) { throw new TypeError("Illegal constructor"); }
        var up = upgradeStack.length ? upgradeStack[upgradeStack.length - 1] : null;
        if (up) {
          upgradeStack[upgradeStack.length - 1] = null;
          Object.setPrototypeOf(up, new.target.prototype);
          return up;
        }
        init = { doc: g.document, name: def.name, ns: HTML_NS };
        this._ce = def;
      }
      this._p = null; this._d = init.doc; this._t = init.name; this._ns = init.ns;
      this._c = new NodeList(); this._a = new Map();
    }
    get nodeType() { return 1; }
    get nodeName() { return this._ns === HTML_NS ? (this._T || (this._T = this._t.toUpperCase())) : this._t; }
    get tagName() { return this.nodeName; }
    get localName() { return this._t; }
    get namespaceURI() { return this._ns; }
    get prefix() { return null; }
    get id() { return this._a.get("id") || ""; }
    set id(v) { setAttr(this, "id", String(v)); }
    get className() { return this._a.get("class") || ""; }
    set className(v) { setAttr(this, "class", String(v)); }
    get classList() { return this._cl || (this._cl = new DOMTokenList(this, "class")); }
    set classList(v) { setAttr(this, "class", String(v)); }
    get slot() { return this._a.get("slot") || ""; }
    set slot(v) { setAttr(this, "slot", String(v)); }
    get attributes() {
      var el = this, out = [];
      this._a.forEach(function (v, k) { out.push(attrObj(el, k, v)); });
      out.item = function (i) { return out[i] || null; };
      out.getNamedItem = function (n) { return el.getAttributeNode(n); };
      out.setNamedItem = function (a) { el.setAttribute(a.name, a.value); };
      out.removeNamedItem = function (n) { el.removeAttribute(n); };
      for (var i = 0; i < out.length; i++) { if (!(out[i].name in out)) { out[out[i].name] = out[i]; } }
      return out;
    }
    _name(n) { n = String(n); return this._ns === HTML_NS ? n.toLowerCase() : n; }
    getAttribute(n) { var v = this._a.get(this._name(n)); return v === undefined ? null : v; }
    setAttribute(n, v) {
      n = this._name(n);
      if (!n || /[\s"'<>\/=]/.test(n)) { throw domEx("InvalidCharacterError", "'" + n + "' is not a valid attribute name."); }
      setAttr(this, n, String(v));
    }
    removeAttribute(n) { removeAttr(this, this._name(n)); }
    hasAttribute(n) { return this._a.has(this._name(n)); }
    toggleAttribute(n, force) {
      n = this._name(n);
      if (this._a.has(n)) { if (force === true) { return true; } removeAttr(this, n); return false; }
      if (force === false) { return false; }
      setAttr(this, n, ""); return true;
    }
    hasAttributes() { return this._a.size > 0; }
    getAttributeNames() { return Array.from(this._a.keys()); }
    getAttributeNS(ns, n) { var v = this._a.get(String(n)); if (v === undefined) { v = this._a.get(String(n).replace(/^.*:/, "")); } return v === undefined ? null : v; }
    setAttributeNS(ns, n, v) { setAttr(this, String(n), String(v)); }
    removeAttributeNS(ns, n) { removeAttr(this, String(n)); }
    hasAttributeNS(ns, n) { return this._a.has(String(n)); }
    getAttributeNode(n) { n = this._name(n); var v = this._a.get(n); return v === undefined ? null : attrObj(this, n, v); }
    getAttributeNodeNS(ns, n) { return this.getAttributeNode(n); }
    setAttributeNode(a) { var old = this.getAttributeNode(a.name); setAttr(this, this._name(a.name), String(a.value)); return old; }
    removeAttributeNode(a) { removeAttr(this, this._name(a.name)); return a; }
    get textContent() { var out = []; textOf(this, out); return out.join(""); }
    set textContent(v) { setText(this._t === "template" && this._content ? this._content : this, v); }
    get innerHTML() { return serializeChildren(this); }
    set innerHTML(html) { setInner(this, html, this); }
    get outerHTML() { var out = []; serialize(this, out); return out.join(""); }
    set outerHTML(html) {
      var p = this._p;
      if (!p) { return; }
      if (p.nodeType === 9) { throw domEx("NoModificationAllowedError", "cannot replace the document element"); }
      var f = parseFragment(this._d, html, p), next = this.nextSibling;
      detach(this);
      insert(p, f, next);
    }
    insertAdjacentElement(pos, el) {
      switch (String(pos).toLowerCase()) {
        case "beforebegin": if (!this._p) { return null; } insert(this._p, el, this); break;
        case "afterbegin": insert(this, el, this._c[0] || null); break;
        case "beforeend": insert(this, el, null); break;
        case "afterend": if (!this._p) { return null; } insert(this._p, el, this.nextSibling); break;
        default: throw domEx("SyntaxError", "The value provided ('" + pos + "') is not one of 'beforeBegin', 'afterBegin', 'beforeEnd', or 'afterEnd'.");
      }
      return el;
    }
    insertAdjacentHTML(pos, html) {
      var p = String(pos).toLowerCase();
      var ctx = p === "beforebegin" || p === "afterend" ? this._p : this;
      if (!ctx) { throw domEx("NoModificationAllowedError", "The element has no parent."); }
      var f = parseFragment(this._d, html, ctx);
      if (f._c.length) { this.insertAdjacentElement(pos, f); }
    }
    insertAdjacentText(pos, text) { this.insertAdjacentElement(pos, this._d.createTextNode(String(text))); }
    get nextElementSibling() { return siblingElement(this, 1); }
    get previousElementSibling() { return siblingElement(this, -1); }
    matches(sel) { return matchAny(this, compile(sel), this); }
    webkitMatchesSelector(sel) { return this.matches(sel); }
    closest(sel) {
      var list = compile(sel);
      for (var n = this; n && n.nodeType === 1; n = n._p) { if (matchAny(n, list, this)) { return n; } }
      return null;
    }
    getBoundingClientRect() { return ZERO_RECT(); }
    getClientRects() { return []; }
    scrollIntoView() {}
    scrollIntoViewIfNeeded() {}
    scrollTo() {}
    scrollBy() {}
    scroll() {}
    get scrollTop() { return this._st || 0; }
    set scrollTop(v) { this._st = +v || 0; }
    get scrollLeft() { return this._sl || 0; }
    set scrollLeft(v) { this._sl = +v || 0; }
    get scrollWidth() { return 0; }
    get scrollHeight() { return 0; }
    get clientWidth() { return 0; }
    get clientHeight() { return 0; }
    get clientTop() { return 0; }
    get clientLeft() { return 0; }
    attachShadow(init) {
      creating = { frag: true, doc: this._d };
      var s = new ShadowRoot();
      s.host = this; s.mode = (init && init.mode) || "open";
      this._shadow = s;
      return s;
    }
    get shadowRoot() { return this._shadow && this._shadow.mode === "open" ? this._shadow : null; }
    animate() { var self = this; return { finished: Promise.resolve(), ready: Promise.resolve(), playState: "finished", cancel: function () {}, finish: function () {}, play: function () {}, pause: function () {}, reverse: function () {}, addEventListener: function () {}, removeEventListener: function () {}, effect: { target: self }, onfinish: null }; }
    getAnimations() { return []; }
    setPointerCapture() {}
    releasePointerCapture() {}
    hasPointerCapture() { return false; }
    requestFullscreen() { return Promise.resolve(); }
    requestPointerLock() {}
    checkVisibility() { return true; }
    _clone(deep, doc) {
      var n = makeElement(doc, this._t, this._ns);
      this._a.forEach(function (v, k) { n._a.set(k, v); });
      if (this._value !== undefined) { n._value = this._value; }
      if (this._checked !== undefined) { n._checked = this._checked; }
      if (this._t === "script") { n._ran = this._ran; }
      if (deep) {
        var from = this._t === "template" && this._content ? this._content : this;
        var to = n._t === "template" && n._content ? n._content : n;
        for (var i = 0; i < from._c.length; i++) { to._c.push(adoptClone(from._c[i]._clone(true, doc), to)); }
      }
      return n;
    }
  }
  mixin(Element, ChildNode);
  mixin(Element, ParentNode, ParentNodeGetters);

  function reflect(C, prop, attr, kind, dflt) {
    attr = attr || prop.toLowerCase();
    var d;
    if (kind === "bool") {
      d = { get: function () { return this._a.has(attr); }, set: function (v) { if (v) { if (!this._a.has(attr)) { setAttr(this, attr, ""); } } else { removeAttr(this, attr); } } };
    } else if (kind === "url") {
      d = { get: function () { var v = this._a.get(attr); return v === undefined ? "" : resolveURL(this, v); }, set: function (v) { setAttr(this, attr, String(v)); } };
    } else if (kind === "num") {
      d = { get: function () { var v = parseInt(this._a.get(attr), 10); return isNaN(v) ? dflt : v; }, set: function (v) { setAttr(this, attr, String(v)); } };
    } else {
      d = { get: function () { var v = this._a.get(attr); return v === undefined ? (dflt || "") : v; }, set: function (v) { setAttr(this, attr, v === null ? "" : String(v)); } };
    }
    d.configurable = true; d.enumerable = true;
    Object.defineProperty(C.prototype, prop, d);
  }
  function reflectAll(C, strs, bools, urls, nums) {
    (strs || []).forEach(function (p) { if (Array.isArray(p)) { reflect(C, p[0], p[1], "str", p[2]); } else { reflect(C, p, null, "str"); } });
    (bools || []).forEach(function (p) { if (Array.isArray(p)) { reflect(C, p[0], p[1], "bool"); } else { reflect(C, p, null, "bool"); } });
    (urls || []).forEach(function (p) { reflect(C, p, null, "url"); });
    (nums || []).forEach(function (p) { reflect(C, p[0], p[1], "num", p[2]); });
  }

  class HTMLElement extends Element {
    get style() { return styleOf(this); }
    set style(v) { setAttr(this, "style", String(v)); }
    get dataset() { return datasetOf(this); }
    get innerText() { return this.textContent; }
    set innerText(v) { this.textContent = v; }
    get outerText() { return this.textContent; }
    get offsetWidth() { return 0; }
    get offsetHeight() { return 0; }
    get offsetTop() { return 0; }
    get offsetLeft() { return 0; }
    get offsetParent() { return null; }
    get isContentEditable() { return false; }
    get contentEditable() { return this._a.get("contenteditable") || "inherit"; }
    set contentEditable(v) { setAttr(this, "contenteditable", String(v)); }
    get tabIndex() { var v = parseInt(this._a.get("tabindex"), 10); return isNaN(v) ? (/^(a|button|input|select|textarea)$/.test(this._t) ? 0 : -1) : v; }
    set tabIndex(v) { setAttr(this, "tabindex", String(v)); }
    click() { dispatch(this, new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })); }
    focus() {
      var d = this._d;
      if (!d || d._active === this) { return; }
      var prev = d._active;
      d._active = this;
      if (prev) { dispatch(prev, new EVENT_CLASSES.FocusEvent("blur")); dispatch(prev, new EVENT_CLASSES.FocusEvent("focusout", { bubbles: true })); }
      dispatch(this, new EVENT_CLASSES.FocusEvent("focus")); dispatch(this, new EVENT_CLASSES.FocusEvent("focusin", { bubbles: true }));
    }
    blur() {
      var d = this._d;
      if (!d || d._active !== this) { return; }
      d._active = null;
      dispatch(this, new EVENT_CLASSES.FocusEvent("blur")); dispatch(this, new EVENT_CLASSES.FocusEvent("focusout", { bubbles: true }));
    }
  }
  reflectAll(HTMLElement, ["title", "lang", "dir", ["accessKey", "accesskey"], "role", "nonce", ["inputMode", "inputmode"], ["enterKeyHint", "enterkeyhint"], "translate"], ["hidden", "inert", "draggable", "spellcheck", "autofocus"]);

  class SVGElement extends Element {
    get style() { return styleOf(this); }
    set style(v) { setAttr(this, "style", String(v)); }
    get dataset() { return datasetOf(this); }
    get className() { var el = this; return { get baseVal() { return el._a.get("class") || ""; }, set baseVal(v) { setAttr(el, "class", String(v)); }, get animVal() { return el._a.get("class") || ""; }, toString: function () { return el._a.get("class") || ""; } }; }
    set className(v) { setAttr(this, "class", String(v)); }
    get ownerSVGElement() { for (var n = this._p; n; n = n._p) { if (n._t === "svg") { return n; } } return null; }
    get viewportElement() { return this.ownerSVGElement; }
    getBBox() { return { x: 0, y: 0, width: 0, height: 0 }; }
    getCTM() { return null; }
    getScreenCTM() { return null; }
    getTotalLength() { return 0; }
    getComputedTextLength() { return 0; }
    getPointAtLength() { return { x: 0, y: 0 }; }
    focus() {}
    blur() {}
  }

  // Tag-specific classes. Each gets the properties scripts read off that tag.
  var TAGS = Object.create(null);
  function tagClass(name, tags, Base, strs, bools, urls, nums) {
    var C = { [name]: class extends (Base || HTMLElement) {} }[name];
    reflectAll(C, strs, bools, urls, nums);
    (tags || []).forEach(function (t) { TAGS[t] = C; });
    return C;
  }
  function urlParts(C) {
    ["protocol", "host", "hostname", "port", "pathname", "search", "hash", "origin", "username", "password"].forEach(function (k) {
      Object.defineProperty(C.prototype, k, {
        get: function () { try { return new g.URL(this.href)[k]; } catch (_) { return ""; } },
        set: function (v) { try { var u = new g.URL(this.href); u[k] = v; setAttr(this, "href", u.href); } catch (_) {} },
        configurable: true,
      });
    });
    C.prototype.toString = function () { return this.href; };
  }
  var CL = {};
  CL.HTMLAnchorElement = tagClass("HTMLAnchorElement", ["a"], null, ["target", "rel", "download", "hreflang", "type", "name", ["referrerPolicy", "referrerpolicy"], "ping"], null, ["href"]);
  urlParts(CL.HTMLAnchorElement);
  Object.defineProperty(CL.HTMLAnchorElement.prototype, "text", { get: function () { return this.textContent; }, set: function (v) { this.textContent = v; }, configurable: true });
  Object.defineProperty(CL.HTMLAnchorElement.prototype, "relList", { get: function () { return this._rl || (this._rl = new DOMTokenList(this, "rel")); }, configurable: true });
  CL.HTMLAreaElement = tagClass("HTMLAreaElement", ["area"], null, ["target", "rel", "alt", "coords", "shape", "download"], null, ["href"]);
  urlParts(CL.HTMLAreaElement);
  CL.HTMLLinkElement = tagClass("HTMLLinkElement", ["link"], null, ["rel", "media", "type", "as", "hreflang", "integrity", "sizes", ["crossOrigin", "crossorigin"], ["referrerPolicy", "referrerpolicy"], ["imageSrcset", "imagesrcset"], ["fetchPriority", "fetchpriority"], "charset"], ["disabled"], ["href"]);
  Object.defineProperty(CL.HTMLLinkElement.prototype, "relList", { get: function () { return this._rl || (this._rl = new DOMTokenList(this, "rel")); }, configurable: true });
  Object.defineProperty(CL.HTMLLinkElement.prototype, "sheet", { get: function () { return null; }, configurable: true });
  CL.HTMLBaseElement = tagClass("HTMLBaseElement", ["base"], null, ["target"], null, ["href"]);
  CL.HTMLImageElement = tagClass("HTMLImageElement", ["img"], null, ["alt", "srcset", "sizes", ["crossOrigin", "crossorigin"], ["useMap", "usemap"], "loading", "decoding", ["referrerPolicy", "referrerpolicy"], "name", "align", ["fetchPriority", "fetchpriority"]], [["isMap", "ismap"]], ["src"], [["width", "width", 0], ["height", "height", 0]]);
  Object.defineProperties(CL.HTMLImageElement.prototype, {
    complete: { get: function () { return true; }, configurable: true },
    naturalWidth: { get: function () { return this.width || 1; }, configurable: true },
    naturalHeight: { get: function () { return this.height || 1; }, configurable: true },
    currentSrc: { get: function () { return this.src; }, configurable: true },
    decode: { value: function () { return Promise.resolve(); }, configurable: true, writable: true },
  });
  CL.HTMLScriptElement = tagClass("HTMLScriptElement", ["script"], null, ["type", "charset", ["crossOrigin", "crossorigin"], "integrity", ["referrerPolicy", "referrerpolicy"], ["htmlFor", "for"], "event", ["fetchPriority", "fetchpriority"]], ["defer", ["noModule", "nomodule"]], ["src"]);
  Object.defineProperties(CL.HTMLScriptElement.prototype, {
    text: { get: function () { return this.textContent; }, set: function (v) { this.textContent = v; }, configurable: true },
    async: { get: function () { return this._async !== undefined ? this._async : (this._a.has("async") || !this._parsed); }, set: function (v) { this._async = !!v; }, configurable: true },
  });
  CL.HTMLScriptElement.supports = function (t) { return t === "classic"; };
  CL.HTMLIFrameElement = tagClass("HTMLIFrameElement", ["iframe", "frame"], null, ["name", "srcdoc", "allow", "sandbox", "loading", ["referrerPolicy", "referrerpolicy"], "width", "height", ["frameBorder", "frameborder"], "scrolling"], [["allowFullscreen", "allowfullscreen"]], ["src"]);
  Object.defineProperties(CL.HTMLIFrameElement.prototype, { contentWindow: { get: function () { return null; }, configurable: true }, contentDocument: { get: function () { return null; }, configurable: true } });
  CL.HTMLSourceElement = tagClass("HTMLSourceElement", ["source"], null, ["type", "srcset", "sizes", "media"], null, ["src"]);
  CL.HTMLTrackElement = tagClass("HTMLTrackElement", ["track"], null, ["kind", "srclang", "label"], ["default"], ["src"]);
  CL.HTMLEmbedElement = tagClass("HTMLEmbedElement", ["embed"], null, ["type", "width", "height"], null, ["src"]);
  CL.HTMLObjectElement = tagClass("HTMLObjectElement", ["object"], null, ["type", "name", "width", "height"], null, ["data"]);
  CL.HTMLMediaElement = tagClass("HTMLMediaElement", [], null, ["preload", ["crossOrigin", "crossorigin"]], ["controls", "loop", "muted", "autoplay", ["playsInline", "playsinline"]], ["src"]);
  Object.assign(CL.HTMLMediaElement.prototype, { play: function () { return Promise.resolve(); }, pause: function () {}, load: function () {}, canPlayType: function () { return ""; }, addTextTrack: function () { return {}; } });
  Object.defineProperties(CL.HTMLMediaElement.prototype, { paused: { get: function () { return true; }, configurable: true }, duration: { get: function () { return NaN; }, configurable: true }, readyState: { get: function () { return 0; }, configurable: true }, ended: { get: function () { return false; }, configurable: true }, currentSrc: { get: function () { return this.src; }, configurable: true }, currentTime: { value: 0, writable: true, configurable: true }, volume: { value: 1, writable: true, configurable: true }, playbackRate: { value: 1, writable: true, configurable: true }, buffered: { get: function () { return { length: 0 }; }, configurable: true } });
  CL.HTMLVideoElement = tagClass("HTMLVideoElement", ["video"], CL.HTMLMediaElement, ["width", "height"], null, ["poster"]);
  CL.HTMLAudioElement = tagClass("HTMLAudioElement", ["audio"], CL.HTMLMediaElement);
  CL.HTMLMetaElement = tagClass("HTMLMetaElement", ["meta"], null, ["name", "content", ["httpEquiv", "http-equiv"], "charset", "media", "scheme"]);
  CL.HTMLTitleElement = tagClass("HTMLTitleElement", ["title"]);
  Object.defineProperty(CL.HTMLTitleElement.prototype, "text", { get: function () { return this.textContent; }, set: function (v) { this.textContent = v; }, configurable: true });
  CL.HTMLStyleElement = tagClass("HTMLStyleElement", ["style"], null, ["media", "type"], ["disabled"]);
  Object.defineProperty(CL.HTMLStyleElement.prototype, "sheet", { get: function () { var el = this; return el._sheet || (el._sheet = { cssRules: [], rules: [], ownerNode: el, disabled: false, insertRule: function (r, i) { this.cssRules.splice(i === undefined ? 0 : i, 0, { cssText: r }); return i || 0; }, deleteRule: function (i) { this.cssRules.splice(i, 1); }, addRule: function () { return -1; }, replaceSync: function () {}, replace: function () { return Promise.resolve(this); } }); }, configurable: true });
  CL.HTMLTemplateElement = tagClass("HTMLTemplateElement", ["template"]);
  Object.defineProperty(CL.HTMLTemplateElement.prototype, "content", { get: function () { return this._content; }, configurable: true });
  CL.HTMLCanvasElement = tagClass("HTMLCanvasElement", ["canvas"], null, null, null, null, [["width", "width", 300], ["height", "height", 150]]);
  function nativeCanvas(el) {
    if (el._nc2 === undefined) { try { el._nc2 = nativeDoc.createElement("canvas"); } catch (_) { el._nc2 = null; } }
    return el._nc2;
  }
  Object.assign(CL.HTMLCanvasElement.prototype, {
    getContext: function (kind, opts) { var c = nativeCanvas(this); try { return c ? c.getContext(kind, opts) : null; } catch (_) { return null; } },
    toDataURL: function () { var c = nativeCanvas(this); try { return c ? c.toDataURL.apply(c, arguments) : "data:,"; } catch (_) { return "data:,"; } },
    toBlob: function (cb) { later(function () { cb(null); }); },
    captureStream: function () { return {}; },
    transferControlToOffscreen: function () { return this; },
  });

  // forms
  function formOf(el) { for (var n = el._p; n; n = n._p) { if (n.nodeType === 1 && n._t === "form") { return n; } } var id = el._a.get("form"); return id && el._d ? el._d.getElementById(id) : null; }
  function labelsOf(el) { var id = el._a.get("id"); var out = []; if (id && el._d) { walk(el._d, function (n) { if (n.nodeType === 1 && n._t === "label" && n._a.get("for") === id) { out.push(n); } }); } return nodeList(out); }
  var FORM_COMMON = { form: { get: function () { return formOf(this); }, configurable: true }, labels: { get: function () { return labelsOf(this); }, configurable: true }, validity: { get: function () { return { valid: true, valueMissing: false, typeMismatch: false, patternMismatch: false, tooLong: false, tooShort: false, rangeUnderflow: false, rangeOverflow: false, stepMismatch: false, badInput: false, customError: false }; }, configurable: true }, validationMessage: { get: function () { return ""; }, configurable: true }, willValidate: { get: function () { return true; }, configurable: true } };
  var FORM_METHODS = { checkValidity: function () { return true; }, reportValidity: function () { return true; }, setCustomValidity: function () {}, select: function () {}, setSelectionRange: function () {}, setRangeText: function () {} };
  function formControl(C) { Object.defineProperties(C.prototype, FORM_COMMON); for (var k in FORM_METHODS) { Object.defineProperty(C.prototype, k, { value: FORM_METHODS[k], writable: true, configurable: true }); } }
  CL.HTMLInputElement = tagClass("HTMLInputElement", ["input"], null, ["name", "placeholder", "accept", "alt", "autocomplete", "pattern", "min", "max", "step", ["dirName", "dirname"], ["formMethod", "formmethod"], ["formTarget", "formtarget"], ["defaultValue", "value"]], ["disabled", "multiple", ["readOnly", "readonly"], "required", ["defaultChecked", "checked"], ["formNoValidate", "formnovalidate"]], ["src"], [["maxLength", "maxlength", -1], ["minLength", "minlength", -1], ["size", "size", 20]]);
  Object.defineProperties(CL.HTMLInputElement.prototype, {
    type: { get: function () { var t = (this._a.get("type") || "text").toLowerCase(); return /^(button|checkbox|color|date|datetime-local|email|file|hidden|image|month|number|password|radio|range|reset|search|submit|tel|text|time|url|week)$/.test(t) ? t : "text"; }, set: function (v) { setAttr(this, "type", String(v)); }, configurable: true },
    value: { get: function () { if (this._value !== undefined) { return this._value; } var v = this._a.get("value"); if (v !== undefined) { return v; } var t = this._a.get("type"); return t === "checkbox" || t === "radio" ? "on" : ""; }, set: function (v) { this._value = v === null ? "" : String(v); tick(); }, configurable: true },
    checked: { get: function () { return this._checked !== undefined ? this._checked : this._a.has("checked"); }, set: function (v) {
      this._checked = !!v; tick();
      if (v && (this._a.get("type") || "").toLowerCase() === "radio" && this._a.has("name")) {
        var self = this, name = this._a.get("name"), root = formOf(this) || this.getRootNode();
        walk(root, function (n) { if (n !== self && n.nodeType === 1 && n._t === "input" && n._a.get("name") === name && (n._a.get("type") || "").toLowerCase() === "radio") { n._checked = false; } });
      }
    }, configurable: true },
    indeterminate: { value: false, writable: true, configurable: true },
    valueAsNumber: { get: function () { var n = parseFloat(this.value); return n; }, set: function (v) { this.value = String(v); }, configurable: true },
    valueAsDate: { get: function () { return null; }, configurable: true },
    files: { get: function () { return null; }, configurable: true },
    selectionStart: { value: 0, writable: true, configurable: true }, selectionEnd: { value: 0, writable: true, configurable: true },
    list: { get: function () { return null; }, configurable: true },
  });
  Object.assign(CL.HTMLInputElement.prototype, { stepUp: function () {}, stepDown: function () {}, showPicker: function () {} });
  formControl(CL.HTMLInputElement);
  CL.HTMLTextAreaElement = tagClass("HTMLTextAreaElement", ["textarea"], null, ["name", "placeholder", "wrap", "autocomplete"], ["disabled", ["readOnly", "readonly"], "required"], null, [["cols", "cols", 20], ["rows", "rows", 2], ["maxLength", "maxlength", -1], ["minLength", "minlength", -1]]);
  Object.defineProperties(CL.HTMLTextAreaElement.prototype, {
    type: { get: function () { return "textarea"; }, configurable: true },
    value: { get: function () { return this._value !== undefined ? this._value : this.textContent; }, set: function (v) { this._value = v === null ? "" : String(v); tick(); }, configurable: true },
    defaultValue: { get: function () { return this.textContent; }, set: function (v) { this.textContent = v; }, configurable: true },
    textLength: { get: function () { return this.value.length; }, configurable: true },
    selectionStart: { value: 0, writable: true, configurable: true }, selectionEnd: { value: 0, writable: true, configurable: true },
  });
  formControl(CL.HTMLTextAreaElement);
  CL.HTMLOptionElement = tagClass("HTMLOptionElement", ["option"], null, null, ["disabled", ["defaultSelected", "selected"]]);
  Object.defineProperties(CL.HTMLOptionElement.prototype, {
    value: { get: function () { var v = this._a.get("value"); return v === undefined ? this.text : v; }, set: function (v) { setAttr(this, "value", String(v)); }, configurable: true },
    text: { get: function () { return this.textContent.replace(/\s+/g, " ").trim(); }, set: function (v) { this.textContent = v; }, configurable: true },
    label: { get: function () { var v = this._a.get("label"); return v === undefined ? this.text : v; }, set: function (v) { setAttr(this, "label", String(v)); }, configurable: true },
    selected: { get: function () {
      if (this._checked !== undefined) { return this._checked; }
      if (this._a.has("selected")) { return true; }
      var sel = selectOf(this);
      if (sel && !sel._a.has("multiple")) { var opts = optionsOf(sel); for (var i = 0; i < opts.length; i++) { if (opts[i]._checked === true || (opts[i]._checked === undefined && opts[i]._a.has("selected"))) { return false; } } return opts[0] === this; }
      return false;
    }, set: function (v) {
      var sel = selectOf(this);
      if (v && sel && !sel._a.has("multiple")) { optionsOf(sel).forEach(function (o) { o._checked = false; }); }
      this._checked = !!v; tick();
    }, configurable: true },
    index: { get: function () { var sel = selectOf(this); return sel ? optionsOf(sel).indexOf(this) : 0; }, configurable: true },
    form: { get: function () { return formOf(this); }, configurable: true },
  });
  function selectOf(o) { for (var n = o._p; n; n = n._p) { if (n.nodeType === 1 && n._t === "select") { return n; } } return null; }
  function optionsOf(sel) { var out = []; walk(sel, function (n) { if (n.nodeType === 1 && n._t === "option") { out.push(n); } }); return out; }
  CL.HTMLOptGroupElement = tagClass("HTMLOptGroupElement", ["optgroup"], null, ["label"], ["disabled"]);
  CL.HTMLSelectElement = tagClass("HTMLSelectElement", ["select"], null, ["name", "autocomplete"], ["disabled", "multiple", "required"], null, [["size", "size", 0]]);
  Object.defineProperties(CL.HTMLSelectElement.prototype, {
    type: { get: function () { return this._a.has("multiple") ? "select-multiple" : "select-one"; }, configurable: true },
    options: { get: function () { var sel = this, o = collection(optionsOf(this)); o.add = function (opt, before) { sel.add(opt, before); }; o.remove = function (i) { sel.remove(i); }; Object.defineProperty(o, "selectedIndex", { get: function () { return sel.selectedIndex; }, set: function (v) { sel.selectedIndex = v; } }); return o; }, configurable: true },
    selectedOptions: { get: function () { return collection(optionsOf(this).filter(function (o) { return o.selected; })); }, configurable: true },
    selectedIndex: { get: function () { var o = optionsOf(this); for (var i = 0; i < o.length; i++) { if (o[i].selected) { return i; } } return -1; }, set: function (v) { var o = optionsOf(this); o.forEach(function (x, i) { x._checked = i === v; }); tick(); }, configurable: true },
    value: { get: function () { var o = optionsOf(this); for (var i = 0; i < o.length; i++) { if (o[i].selected) { return o[i].value; } } return ""; }, set: function (v) { var o = optionsOf(this), hit = false; v = String(v); o.forEach(function (x) { x._checked = !hit && x.value === v; if (x._checked) { hit = true; } }); tick(); }, configurable: true },
    length: { get: function () { return optionsOf(this).length; }, configurable: true },
  });
  Object.assign(CL.HTMLSelectElement.prototype, {
    add: function (opt, before) { insert(this, opt, before instanceof Node ? before : (typeof before === "number" ? optionsOf(this)[before] || null : null)); },
    item: function (i) { return optionsOf(this)[i] || null; },
    namedItem: function (n) { return optionsOf(this).filter(function (o) { return o._a.get("id") === n || o._a.get("name") === n; })[0] || null; },
  });
  var elRemove = ChildNode.remove;
  CL.HTMLSelectElement.prototype.remove = function (i) { if (arguments.length === 0) { return elRemove.call(this); } var o = optionsOf(this)[i]; if (o) { detach(o); } };
  formControl(CL.HTMLSelectElement);
  CL.HTMLButtonElement = tagClass("HTMLButtonElement", ["button"], null, ["name", "value", ["formMethod", "formmethod"], ["formTarget", "formtarget"]], ["disabled", ["formNoValidate", "formnovalidate"]]);
  Object.defineProperty(CL.HTMLButtonElement.prototype, "type", { get: function () { var t = (this._a.get("type") || "submit").toLowerCase(); return t === "button" || t === "reset" ? t : "submit"; }, set: function (v) { setAttr(this, "type", String(v)); }, configurable: true });
  formControl(CL.HTMLButtonElement);
  CL.HTMLFormElement = tagClass("HTMLFormElement", ["form"], null, ["name", "method", "enctype", "encoding", "target", "autocomplete", ["acceptCharset", "accept-charset"]], [["noValidate", "novalidate"]], ["action"]);
  Object.defineProperties(CL.HTMLFormElement.prototype, {
    elements: { get: function () { var f = this, out = []; walk(this, function (n) { if (n.nodeType === 1 && /^(input|select|textarea|button|fieldset|output|object)$/.test(n._t)) { out.push(n); } }); var c = collection(out); out.forEach(function (n) { var nm = n._a.get("name") || n._a.get("id"); if (nm && !(nm in c)) { c[nm] = n; } }); return c; }, configurable: true },
    length: { get: function () { return this.elements.length; }, configurable: true },
  });
  Object.assign(CL.HTMLFormElement.prototype, {
    submit: function () {},
    requestSubmit: function () { dispatch(this, new EVENT_CLASSES.SubmitEvent("submit", { bubbles: true, cancelable: true })); },
    reset: function () { walk(this, function (n) { if (n.nodeType === 1) { n._value = undefined; n._checked = undefined; } }); dispatch(this, new Event("reset", { bubbles: true })); },
    checkValidity: function () { return true; }, reportValidity: function () { return true; },
  });
  CL.HTMLLabelElement = tagClass("HTMLLabelElement", ["label"], null, [["htmlFor", "for"]]);
  Object.defineProperties(CL.HTMLLabelElement.prototype, { control: { get: function () { var id = this._a.get("for"); return id ? this._d.getElementById(id) : select(this, "input,select,textarea,button", true); }, configurable: true }, form: { get: function () { return formOf(this); }, configurable: true } });
  CL.HTMLFieldSetElement = tagClass("HTMLFieldSetElement", ["fieldset"], null, ["name"], ["disabled"]);
  CL.HTMLOutputElement = tagClass("HTMLOutputElement", ["output"], null, ["name"]);
  CL.HTMLTableElement = tagClass("HTMLTableElement", ["table"], null, ["border", "summary", "width", ["cellPadding", "cellpadding"], ["cellSpacing", "cellspacing"]]);
  Object.defineProperties(CL.HTMLTableElement.prototype, {
    rows: { get: function () { return collection(select(this, "tr", false)); }, configurable: true },
    tBodies: { get: function () { return collection(elementChildren(this).filter(function (n) { return n._t === "tbody"; })); }, configurable: true },
    tHead: { get: function () { return elementChildren(this).filter(function (n) { return n._t === "thead"; })[0] || null; }, configurable: true },
    tFoot: { get: function () { return elementChildren(this).filter(function (n) { return n._t === "tfoot"; })[0] || null; }, configurable: true },
  });
  function insertRowInto(section, index) {
    var tr = section._d.createElement("tr"), rows = elementChildren(section).filter(function (n) { return n._t === "tr"; });
    insert(section, tr, index === undefined || index < 0 || index >= rows.length ? null : rows[index]);
    return tr;
  }
  Object.assign(CL.HTMLTableElement.prototype, {
    createTBody: function () { var b = this._d.createElement("tbody"); insert(this, b, null); return b; },
    createTHead: function () { var h = this.tHead; if (!h) { h = this._d.createElement("thead"); insert(this, h, this._c[0] || null); } return h; },
    createTFoot: function () { var f = this.tFoot; if (!f) { f = this._d.createElement("tfoot"); insert(this, f, null); } return f; },
    insertRow: function (i) { var b = this.tBodies[this.tBodies.length - 1] || this.createTBody(); return insertRowInto(b, i); },
    deleteRow: function (i) { var r = this.rows[i < 0 ? this.rows.length - 1 : i]; if (r) { detach(r); } },
  });
  CL.HTMLTableSectionElement = tagClass("HTMLTableSectionElement", ["tbody", "thead", "tfoot"]);
  Object.defineProperty(CL.HTMLTableSectionElement.prototype, "rows", { get: function () { return collection(elementChildren(this).filter(function (n) { return n._t === "tr"; })); }, configurable: true });
  Object.assign(CL.HTMLTableSectionElement.prototype, { insertRow: function (i) { return insertRowInto(this, i); }, deleteRow: function (i) { var r = this.rows[i < 0 ? this.rows.length - 1 : i]; if (r) { detach(r); } } });
  CL.HTMLTableRowElement = tagClass("HTMLTableRowElement", ["tr"]);
  Object.defineProperties(CL.HTMLTableRowElement.prototype, {
    cells: { get: function () { return collection(elementChildren(this).filter(function (n) { return n._t === "td" || n._t === "th"; })); }, configurable: true },
    rowIndex: { get: function () { var t = this.closest("table"); return t ? t.rows.indexOf(this) : -1; }, configurable: true },
    sectionRowIndex: { get: function () { return this._p ? elementChildren(this._p).indexOf(this) : -1; }, configurable: true },
  });
  Object.assign(CL.HTMLTableRowElement.prototype, {
    insertCell: function (i) { var td = this._d.createElement("td"), cells = this.cells; insert(this, td, i === undefined || i < 0 || i >= cells.length ? null : cells[i]); return td; },
    deleteCell: function (i) { var c = this.cells[i < 0 ? this.cells.length - 1 : i]; if (c) { detach(c); } },
  });
  CL.HTMLTableCellElement = tagClass("HTMLTableCellElement", ["td", "th"], null, ["headers", "scope", "abbr", "align", "width"], null, null, [["colSpan", "colspan", 1], ["rowSpan", "rowspan", 1]]);
  Object.defineProperty(CL.HTMLTableCellElement.prototype, "cellIndex", { get: function () { return this._p ? elementChildren(this._p).indexOf(this) : -1; }, configurable: true });
  [["HTMLDivElement", ["div"]], ["HTMLSpanElement", ["span"]], ["HTMLParagraphElement", ["p"]], ["HTMLHeadingElement", ["h1", "h2", "h3", "h4", "h5", "h6"]], ["HTMLUListElement", ["ul"]], ["HTMLOListElement", ["ol"]], ["HTMLLIElement", ["li"]], ["HTMLPreElement", ["pre"]], ["HTMLBodyElement", ["body"]], ["HTMLHeadElement", ["head"]], ["HTMLHtmlElement", ["html"]], ["HTMLBRElement", ["br"]], ["HTMLHRElement", ["hr"]], ["HTMLQuoteElement", ["blockquote", "q"]], ["HTMLDListElement", ["dl"]], ["HTMLPictureElement", ["picture"]], ["HTMLDetailsElement", ["details"]], ["HTMLDialogElement", ["dialog"]], ["HTMLSlotElement", ["slot"]], ["HTMLTimeElement", ["time"]], ["HTMLDataElement", ["data"]], ["HTMLMapElement", ["map"]], ["HTMLProgressElement", ["progress"]], ["HTMLMeterElement", ["meter"]], ["HTMLLegendElement", ["legend"]], ["HTMLTableCaptionElement", ["caption"]], ["HTMLTableColElement", ["col", "colgroup"]], ["HTMLMenuElement", ["menu"]], ["HTMLModElement", ["ins", "del"]], ["HTMLDataListElement", ["datalist"]]].forEach(function (p) { CL[p[0]] = tagClass(p[0], p[1]); });
  reflectAll(CL.HTMLDetailsElement, null, ["open"]);
  reflectAll(CL.HTMLDialogElement, null, ["open"]);
  Object.assign(CL.HTMLDialogElement.prototype, { show: function () { this.open = true; }, showModal: function () { this.open = true; }, close: function () { this.open = false; dispatch(this, new Event("close")); } });
  Object.assign(CL.HTMLSlotElement.prototype, { assignedNodes: function () { return []; }, assignedElements: function () { return []; } });
  reflectAll(CL.HTMLOListElement, ["type"], ["reversed"], null, [["start", "start", 1]]);
  reflectAll(CL.HTMLLIElement, null, null, null, [["value", "value", 0]]);
  CL.HTMLUnknownElement = tagClass("HTMLUnknownElement", []);
  var SVGGraphicsElement = { SVGGraphicsElement: class extends SVGElement {} }.SVGGraphicsElement;
  var SVGSVGElement = { SVGSVGElement: class extends SVGGraphicsElement { createSVGRect() { return { x: 0, y: 0, width: 0, height: 0 }; } createSVGPoint() { return { x: 0, y: 0, matrixTransform: function () { return this; } }; } createSVGMatrix() { return { a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 }; } } }.SVGSVGElement;
  var MathMLElement = { MathMLElement: class extends Element { get style() { return styleOf(this); } get dataset() { return datasetOf(this); } } }.MathMLElement;

  function makeElement(doc, name, ns) {
    var C;
    if (ns === HTML_NS) {
      var def = ceByName.size ? ceByName.get(name) : undefined;
      if (def) {
        var el;
        try { el = new def.ctor(); } catch (e) { report(e); el = null; }
        if (el instanceof Element) { el._d = doc; el._ce = def; return el; }
      }
      C = TAGS[name] || (name.indexOf("-") > 0 ? HTMLElement : CL.HTMLUnknownElement);
    } else if (ns === SVG_NS) { C = name === "svg" ? SVGSVGElement : SVGGraphicsElement; }
    else if (ns === MATH_NS) { C = MathMLElement; }
    else { C = Element; }
    creating = { el: true, doc: doc, name: name, ns: ns };
    var n = new C();
    if (name === "template" && ns === HTML_NS) { creating = { frag: true, doc: doc }; n._content = new DocumentFragment(); }
    return n;
  }

  // ── document ──────────────────────────────────────────────────────────────
  function firstByTag(doc, tag) { var root = doc.documentElement; if (!root) { return null; } var c = root._c; for (var i = 0; i < c.length; i++) { if (c[i].nodeType === 1 && c[i]._t === tag) { return c[i]; } } return null; }
  class Document extends Node {
    constructor() {
      super();
      this._p = null; this._d = null; this._c = new NodeList(); this._active = null; this._ready = "complete";
    }
    get nodeType() { return 9; }
    get nodeName() { return "#document"; }
    get documentElement() { var c = this._c; for (var i = 0; i < c.length; i++) { if (c[i].nodeType === 1) { return c[i]; } } return null; }
    get doctype() { var c = this._c; for (var i = 0; i < c.length; i++) { if (c[i].nodeType === 10) { return c[i]; } } return null; }
    get head() { return firstByTag(this, "head"); }
    get body() { return firstByTag(this, "body") || firstByTag(this, "frameset"); }
    set body(v) { var old = this.body; if (old) { old._p.replaceChild(v, old); } else if (this.documentElement) { this.documentElement.appendChild(v); } }
    get title() { var t = select(this, "title", true); return t ? t.textContent.replace(/\s+/g, " ").trim() : ""; }
    set title(v) {
      var t = select(this, "title", true);
      if (!t) { t = this.createElement("title"); var h = this.head; if (h) { h.appendChild(t); } else { return; } }
      t.textContent = String(v);
    }
    get readyState() { return this._ready; }
    get defaultView() { return this === g.document ? g : null; }
    get location() { return this === g.document ? g.location : null; }
    set location(v) { if (this === g.document) { g.location.href = v; } }
    get URL() { return this === g.document ? String(g.location.href) : "about:blank"; }
    get documentURI() { return this.URL; }
    get domain() { return this === g.document ? String(g.location.hostname) : ""; }
    set domain(v) {}
    get referrer() { try { return this === g.document ? nativeDoc.referrer || "" : ""; } catch (_) { return ""; } }
    get cookie() { try { return this === g.document ? nativeDoc.cookie : ""; } catch (_) { return ""; } }
    set cookie(v) { try { if (this === g.document) { nativeDoc.cookie = v; } } catch (_) {} }
    get compatMode() { return "CSS1Compat"; }
    get characterSet() { return "UTF-8"; }
    get charset() { return "UTF-8"; }
    get inputEncoding() { return "UTF-8"; }
    get contentType() { return "text/html"; }
    get visibilityState() { return "visible"; }
    get hidden() { return false; }
    get activeElement() { return this._active && connected(this._active) ? this._active : this.body; }
    get currentScript() { return currentScript; }
    get scrollingElement() { return this.documentElement; }
    get fullscreenElement() { return null; }
    get pictureInPictureElement() { return null; }
    get pointerLockElement() { return null; }
    get designMode() { return "off"; }
    set designMode(v) {}
    get dir() { var r = this.documentElement; return r ? r._a.get("dir") || "" : ""; }
    get lastModified() { return new Date().toLocaleString(); }
    get styleSheets() { return []; }
    get adoptedStyleSheets() { return this._ass || (this._ass = []); }
    set adoptedStyleSheets(v) { this._ass = v; }
    get fonts() { return this._fonts || (this._fonts = { ready: Promise.resolve(), status: "loaded", check: function () { return true; }, load: function () { return Promise.resolve([]); }, add: function () {}, delete: function () {}, forEach: function () {}, addEventListener: function () {}, removeEventListener: function () {}, size: 0 }); }
    get forms() { return collection(select(this, "form", false)); }
    get images() { return collection(select(this, "img", false)); }
    get links() { return collection(select(this, "a[href],area[href]", false)); }
    get scripts() { return collection(select(this, "script", false)); }
    get embeds() { return collection(select(this, "embed", false)); }
    get anchors() { return collection(select(this, "a[name]", false)); }
    get implementation() {
      var doc = this;
      return {
        createHTMLDocument: function (title) {
          var d = newDocument("<!DOCTYPE html><html><head></head><body></body></html>");
          if (title !== undefined) { var t = d.createElement("title"); t.textContent = String(title); d.head.appendChild(t); }
          return d;
        },
        createDocument: function (ns, qname) { var d = new Document(); if (qname) { d.appendChild(d.createElementNS(ns, qname)); } return d; },
        createDocumentType: function (name, pub, sys) { return new DocumentType(doc, name, pub, sys); },
        hasFeature: function () { return true; },
      };
    }
    get textContent() { return null; }
    createElement(name) {
      name = String(name);
      if (!name || !/^[A-Za-z_:][^\s<>\/=]*$/.test(name)) { throw domEx("InvalidCharacterError", "The tag name provided ('" + name + "') is not a valid name."); }
      return makeElement(this, name.toLowerCase(), HTML_NS);
    }
    createElementNS(ns, qname) {
      qname = String(qname);
      var local = qname.replace(/^.*:/, "");
      if (ns === HTML_NS || ns === null || ns === undefined || ns === "") { return makeElement(this, ns === HTML_NS ? local.toLowerCase() : local, ns === HTML_NS ? HTML_NS : (ns || "")); }
      return makeElement(this, local, String(ns));
    }
    createTextNode(v) { creating = { text: true, doc: this }; return new Text(String(v)); }
    createComment(v) { creating = { text: true, doc: this }; return new Comment(String(v)); }
    createCDATASection(v) { return this.createTextNode(v); }
    createProcessingInstruction(t, v) { return this.createComment("?" + t + " " + v + "?"); }
    createDocumentFragment() { creating = { frag: true, doc: this }; return new DocumentFragment(); }
    createAttribute(name) { return attrObj(null, String(name).toLowerCase(), ""); }
    createEvent(kind) {
      var C = EVENT_CLASSES[String(kind).replace(/s$/, "")] || EVENT_CLASSES[String(kind)] || (/^html/i.test(kind) ? Event : (/mouse/i.test(kind) ? MouseEvent : (/ui/i.test(kind) ? UIEvent : (/key/i.test(kind) ? EVENT_CLASSES.KeyboardEvent : Event))));
      return new C("");
    }
    createRange() { return new Range(this); }
    createTreeWalker(root, show, filter) { return new TreeWalker(root, show, filter); }
    createNodeIterator(root, show, filter) { return new TreeWalker(root, show, filter); }
    importNode(n, deep) { return n._clone(!!deep, this); }
    adoptNode(n) { if (n._p) { detach(n); } adopt(n, this); return n; }
    getElementById(id) { return byId(this, id); }
    getElementsByName(name) { name = String(name); var out = []; walk(this, function (n) { if (n.nodeType === 1 && n._a.get("name") === name) { out.push(n); } }); return nodeList(out); }
    elementFromPoint() { return this.body; }
    elementsFromPoint() { var b = this.body; return b ? [b, this.documentElement] : []; }
    caretRangeFromPoint() { return null; }
    getSelection() { return g.getSelection(); }
    hasFocus() { return true; }
    execCommand() { return false; }
    queryCommandSupported() { return false; }
    queryCommandEnabled() { return false; }
    exitFullscreen() { return Promise.resolve(); }
    exitPointerLock() {}
    getAnimations() { return []; }
    startViewTransition(cb) { var p = Promise.resolve().then(function () { return cb && cb(); }); return { finished: p, ready: p, updateCallbackDone: p, skipTransition: function () {} }; }
    open() { return this; }
    close() {}
    write() { docWrite(this, Array.prototype.join.call(arguments, "")); }
    writeln() { docWrite(this, Array.prototype.join.call(arguments, "") + "\n"); }
    _clone(deep) { var d = new Document(); if (deep) { for (var i = 0; i < this._c.length; i++) { d._c.push(adoptClone(this._c[i]._clone(true, d), d)); } } return d; }
  }
  mixin(Document, ParentNode, ParentNodeGetters);
  var writeAfter = null;
  function docWrite(doc, html) {
    var f = parseFragment(doc, html, doc.body, true);
    if (!f._c.length) { return; }
    var last = f._c[f._c.length - 1];
    var anchor = writeAfter && writeAfter._p ? writeAfter : (currentScript && currentScript._p && currentScript._d === doc ? currentScript : null);
    if (anchor && anchor._p.nodeType === 1 && anchor._p._t !== "head") { insert(anchor._p, f, anchor.nextSibling); }
    else { var b = doc.body || doc.documentElement; if (!b) { return; } insert(b, f, null); }
    if (anchor) { writeAfter = last; }
  }
  function newDocument(html) {
    var d = new Document();
    var tree;
    try { tree = JSON.parse(g.__seParseHTML(html, false)); } catch (e) { report(e); tree = []; }
    buildInto(d, d, tree, true);
    return d;
  }

  // ── Range, TreeWalker, selection ──────────────────────────────────────────
  class Range {
    constructor(doc) { this._doc = doc || g.document; this.startContainer = this._doc; this.endContainer = this._doc; this.startOffset = 0; this.endOffset = 0; }
    get collapsed() { return this.startContainer === this.endContainer && this.startOffset === this.endOffset; }
    get commonAncestorContainer() { var a = this.startContainer; while (a && !a.contains(this.endContainer)) { a = a._p; } return a || this._doc; }
    setStart(n, o) { this.startContainer = n; this.startOffset = o; }
    setEnd(n, o) { this.endContainer = n; this.endOffset = o; }
    setStartBefore(n) { this.setStart(n._p, n._p._c.indexOf(n)); }
    setStartAfter(n) { this.setStart(n._p, n._p._c.indexOf(n) + 1); }
    setEndBefore(n) { this.setEnd(n._p, n._p._c.indexOf(n)); }
    setEndAfter(n) { this.setEnd(n._p, n._p._c.indexOf(n) + 1); }
    selectNode(n) { this.setStartBefore(n); this.setEndAfter(n); }
    selectNodeContents(n) { this.setStart(n, 0); this.setEnd(n, n._c ? n._c.length : n._v.length); }
    collapse(toStart) { if (toStart) { this.setEnd(this.startContainer, this.startOffset); } else { this.setStart(this.endContainer, this.endOffset); } }
    cloneRange() { var r = new Range(this._doc); r.setStart(this.startContainer, this.startOffset); r.setEnd(this.endContainer, this.endOffset); return r; }
    _nodes() { var s = this.startContainer; if (s !== this.endContainer || !s._c) { return []; } return s._c.slice(this.startOffset, this.endOffset); }
    deleteContents() { this._nodes().forEach(function (n) { detach(n); }); this.collapse(true); }
    extractContents() { var f = this._doc.createDocumentFragment(); this._nodes().forEach(function (n) { f.appendChild(n); }); this.collapse(true); return f; }
    cloneContents() { var f = this._doc.createDocumentFragment(); this._nodes().forEach(function (n) { f.appendChild(n.cloneNode(true)); }); return f; }
    insertNode(n) { var s = this.startContainer; if (s._c) { insert(s, n, s._c[this.startOffset] || null); } else if (s._p) { insert(s._p, n, s); } }
    surroundContents(n) { n.appendChild(this.extractContents()); this.insertNode(n); }
    createContextualFragment(html) { var ctx = this.startContainer; return parseFragment(this._doc, html, ctx && ctx.nodeType === 1 ? ctx : null, true); }
    getBoundingClientRect() { return ZERO_RECT(); }
    getClientRects() { return []; }
    detach() {}
    toString() { var out = []; this._nodes().forEach(function (n) { out.push(n.textContent || ""); }); return out.join(""); }
  }
  class TreeWalker {
    constructor(root, show, filter) { this.root = root; this.whatToShow = show === undefined || show === null ? 0xFFFFFFFF : show >>> 0; this.filter = filter || null; this.currentNode = root; this.referenceNode = root; }
    _ok(n) {
      if (!((this.whatToShow >>> (n.nodeType - 1)) & 1)) { return 3; }
      var f = this.filter;
      if (!f) { return 1; }
      return typeof f === "function" ? f(n) : f.acceptNode(n);
    }
    _next(n, skipKids) {
      if (!skipKids && n._c && n._c.length) { return n._c[0]; }
      while (n && n !== this.root) { var s = n.nextSibling; if (s) { return s; } n = n._p; }
      return null;
    }
    nextNode() {
      var n = this.currentNode, skip = false;
      for (;;) {
        n = this._next(n, skip);
        if (!n) { return null; }
        var r = this._ok(n);
        if (r === 1) { this.currentNode = n; return n; }
        skip = r === 2;
      }
    }
    previousNode() {
      var n = this.currentNode;
      while (n && n !== this.root) {
        var p = n.previousSibling;
        if (p) { while (p._c && p._c.length) { p = p._c[p._c.length - 1]; } n = p; } else { n = n._p; }
        if (n && this._ok(n) === 1) { this.currentNode = n; return n; }
      }
      return null;
    }
    parentNode() { var n = this.currentNode; while (n && n !== this.root) { n = n._p; if (n && this._ok(n) === 1) { this.currentNode = n; return n; } } return null; }
    firstChild() { var c = this.currentNode._c || []; for (var i = 0; i < c.length; i++) { if (this._ok(c[i]) === 1) { this.currentNode = c[i]; return c[i]; } } return null; }
    lastChild() { var c = this.currentNode._c || []; for (var i = c.length - 1; i >= 0; i--) { if (this._ok(c[i]) === 1) { this.currentNode = c[i]; return c[i]; } } return null; }
    nextSibling() { for (var n = this.currentNode.nextSibling; n; n = n.nextSibling) { if (this._ok(n) === 1) { this.currentNode = n; return n; } } return null; }
    previousSibling() { for (var n = this.currentNode.previousSibling; n; n = n.previousSibling) { if (this._ok(n) === 1) { this.currentNode = n; return n; } } return null; }
    detach() {}
  }
  var NodeFilter = { FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3, SHOW_ALL: 0xFFFFFFFF, SHOW_ELEMENT: 1, SHOW_ATTRIBUTE: 2, SHOW_TEXT: 4, SHOW_CDATA_SECTION: 8, SHOW_PROCESSING_INSTRUCTION: 64, SHOW_COMMENT: 128, SHOW_DOCUMENT: 256, SHOW_DOCUMENT_TYPE: 512, SHOW_DOCUMENT_FRAGMENT: 1024 };
  var selection = { rangeCount: 0, anchorNode: null, focusNode: null, anchorOffset: 0, focusOffset: 0, isCollapsed: true, type: "None", removeAllRanges: function () {}, addRange: function () {}, getRangeAt: function () { return new Range(g.document); }, collapse: function () {}, selectAllChildren: function () {}, empty: function () {}, toString: function () { return ""; }, containsNode: function () { return false; } };

  // ── observers that report every target as visible once ───────────────────
  function onceObserver(name, entryOf) {
    return { [name]: class {
      constructor(cb, opts) { this._cb = cb; this._seen = new Set(); this.root = (opts && opts.root) || null; this.rootMargin = (opts && opts.rootMargin) || "0px"; this.thresholds = [0]; }
      observe(el) {
        if (!el || this._seen.has(el)) { return; }
        this._seen.add(el);
        var self = this;
        later(function () { if (self._seen.has(el)) { try { self._cb.call(self, [entryOf(el)], self); } catch (e) { report(e); } } });
      }
      unobserve(el) { this._seen.delete(el); }
      disconnect() { this._seen.clear(); }
      takeRecords() { return []; }
    } }[name];
  }
  var IntersectionObserver = onceObserver("IntersectionObserver", function (el) { var r = ZERO_RECT(); return { target: el, isIntersecting: true, intersectionRatio: 1, boundingClientRect: r, intersectionRect: r, rootBounds: null, time: g.performance.now() }; });
  var ResizeObserver = onceObserver("ResizeObserver", function (el) { var box = [{ inlineSize: 0, blockSize: 0 }]; return { target: el, contentRect: ZERO_RECT(), borderBoxSize: box, contentBoxSize: box, devicePixelContentBoxSize: box }; });

  // ── computed style ────────────────────────────────────────────────────────
  var INLINE = /^(a|abbr|b|bdi|bdo|br|cite|code|data|dfn|em|i|kbd|label|mark|q|s|samp|small|span|strong|sub|sup|time|u|var|wbr|img|input|select|textarea|button|svg|canvas|video|audio|iframe|picture|source)$/;
  var NODISPLAY = /^(script|style|head|meta|link|title|template|base|noscript|datalist|param|area)$/;
  function getComputedStyle(el) {
    var inline = el && el._a ? parseStyle(el._a.get("style")) : new Map();
    function value(k) {
      var v = inline.get(k);
      if (v !== undefined) { return v.replace(/\s*!important$/, ""); }
      if (k === "display") { if (!el || !el._t) { return "block"; } if (el._a.has("hidden") || NODISPLAY.test(el._t)) { return "none"; } return INLINE.test(el._t) ? "inline" : "block"; }
      if (k === "visibility") { return "visible"; }
      if (k === "position") { return "static"; }
      if (k === "opacity") { return "1"; }
      return "";
    }
    return new Proxy({}, {
      get: function (t, k) {
        if (typeof k !== "string") { return undefined; }
        if (k === "getPropertyValue") { return function (n) { return value(String(n)); }; }
        if (k === "getPropertyPriority") { return function () { return ""; }; }
        if (k === "length") { return inline.size; }
        if (k === "item") { return function (i) { return Array.from(inline.keys())[i] || ""; }; }
        if (k === "cssText") { return styleText(inline); }
        return value(kebab(k));
      },
      has: function (t, k) { return typeof k === "string"; },
    });
  }

  // ── install ───────────────────────────────────────────────────────────────
  var doc = newDocument(String(g.__sePageHTML()));
  if (!doc.documentElement) {
    var he = makeElement(doc, "html", HTML_NS); he._p = doc; doc._c.push(he);
    he.appendChild(makeElement(doc, "head", HTML_NS)); he.appendChild(makeElement(doc, "body", HTML_NS));
  }
  doc._ready = "loading";
  walk(doc, function (n) { if (n.nodeType === 1 && n._t === "script") { n._parsed = true; } });

  var exported = {
    Event: Event, EventTarget: EventTarget, Node: Node, Element: Element, HTMLElement: HTMLElement, SVGElement: SVGElement,
    SVGGraphicsElement: SVGGraphicsElement, SVGSVGElement: SVGSVGElement, MathMLElement: MathMLElement,
    CharacterData: CharacterData, Text: Text, Comment: Comment, DocumentType: DocumentType, DocumentFragment: DocumentFragment,
    ShadowRoot: ShadowRoot, Document: Document, HTMLDocument: Document, XMLDocument: Document, NodeList: NodeList, HTMLCollection: HTMLCollection,
    DOMTokenList: DOMTokenList, MutationObserver: MutationObserver, WebKitMutationObserver: MutationObserver,
    IntersectionObserver: IntersectionObserver, ResizeObserver: ResizeObserver, Range: Range, TreeWalker: TreeWalker, NodeIterator: TreeWalker,
    NodeFilter: NodeFilter, customElements: customElements, getComputedStyle: getComputedStyle,
  };
  var k;
  for (k in EVENT_CLASSES) { exported[k] = EVENT_CLASSES[k]; }
  for (k in CL) { exported[k] = CL[k]; }
  for (k in exported) { try { Object.defineProperty(g, k, { value: exported[k], writable: true, configurable: true, enumerable: false }); } catch (_) { try { g[k] = exported[k]; } catch (__) {} } }
  g.Image = function Image(w, h) { var i = doc.createElement("img"); if (w !== undefined) { i.width = w; } if (h !== undefined) { i.height = h; } return i; };
  g.Image.prototype = CL.HTMLImageElement.prototype;
  g.Audio = function Audio(src) { var a = doc.createElement("audio"); if (src) { a.src = src; } return a; };
  g.Audio.prototype = CL.HTMLAudioElement.prototype;
  g.Option = function Option(text, value, defSel, sel) { var o = doc.createElement("option"); if (text !== undefined) { o.textContent = String(text); } if (value !== undefined) { o.setAttribute("value", String(value)); } if (defSel) { o.setAttribute("selected", ""); } if (sel) { o.selected = true; } return o; };
  g.Option.prototype = CL.HTMLOptionElement.prototype;
  g.DOMParser = function DOMParser() {};
  g.DOMParser.prototype.parseFromString = function (s) { return newDocument(String(s)); };
  g.XMLSerializer = function XMLSerializer() {};
  g.XMLSerializer.prototype.serializeToString = function (n) { var out = []; serialize(n, out); return out.join(""); };
  g.getSelection = function () { return selection; };
  try { Object.defineProperty(g, "document", { value: doc, writable: true, configurable: true, enumerable: true }); } catch (_) { g.document = doc; }

  // window as an event target. Events the bridge raises itself (popstate,
  // hashchange, scroll, message, storage) still arrive through its own
  // registry, so those types are forwarded once.
  var nativeAdd = g.addEventListener;
  var forwarded = Object.create(null);
  var NATIVE_TYPES = { popstate: 1, hashchange: 1, scroll: 1, message: 1, storage: 1, resize: 1 };
  g.addEventListener = function addEventListener(type, fn, opts) {
    type = String(type);
    if (NATIVE_TYPES[type] && !forwarded[type] && typeof nativeAdd === "function") {
      forwarded[type] = true;
      try { nativeAdd.call(g, type, function (e) { fire(g, asEvent(e), null, 2); }); } catch (_) {}
    }
    addListener(g, type, fn, opts);
  };
  g.removeEventListener = function removeEventListener(type, fn, opts) { removeListener(g, type, fn, opts); };
  g.dispatchEvent = function dispatchEvent(ev) {
    ev = asEvent(ev);
    if (ev.type === "load" && doc._ready !== "complete") { doc._ready = "complete"; fireSimple(doc, "readystatechange"); }
    return dispatch(g, ev);
  };
  var docDispatch = doc.dispatchEvent;
  doc.dispatchEvent = function (ev) {
    if (ev && ev.type === "DOMContentLoaded" && doc._ready === "loading") { doc._ready = "interactive"; fireSimple(doc, "readystatechange"); }
    return docDispatch.call(doc, ev);
  };

  // Functions of this file answer toString() the way built-ins do: feature
  // tests (Sizzle's rnative) take the fast paths only for native-looking
  // methods, and a script-defined DOM is an obvious tell otherwise.
  var natives = new WeakSet();
  var realToString = Function.prototype.toString;
  // ── platform interfaces a page names but the engine has no object for ────
  // Only where the name is still undefined: a real one from the bridge or the
  // prelude always wins. Enough for `instanceof`, `class X extends File` and
  // feature tests; none of these does I/O.
  function define(name, value) { if (typeof g[name] === "undefined") { try { g[name] = value; } catch (_) {} } }
  function fromInstance(name, get) {
    if (typeof g[name] !== "undefined") { return; }
    var inst = null; try { inst = get(); } catch (_) {}
    var proto = inst && Object.getPrototypeOf(inst);
    if (proto && proto !== Object.prototype && typeof proto.constructor === "function" && proto.constructor !== Object) { define(name, proto.constructor); return; }
    var F = function () { throw new TypeError("Illegal constructor"); };
    Object.defineProperty(F, "name", { value: name });
    if (inst && typeof inst === "object") { try { Object.defineProperty(F, Symbol.hasInstance, { value: function (v) { return v === inst; } }); } catch (_) {} }
    define(name, F);
  }
  fromInstance("Storage", function () { return g.localStorage; });
  fromInstance("History", function () { return g.history; });
  fromInstance("Location", function () { return g.location; });
  fromInstance("Navigator", function () { return g.navigator; });
  fromInstance("Screen", function () { return g.screen; });
  fromInstance("Performance", function () { return g.performance; });
  fromInstance("Crypto", function () { return g.crypto; });
  fromInstance("SubtleCrypto", function () { return g.crypto && g.crypto.subtle; });
  fromInstance("AbortSignal", function () { return new g.AbortController().signal; });
  fromInstance("MediaQueryList", function () { return g.matchMedia("(min-width: 1px)"); });
  fromInstance("CustomElementRegistry", function () { return g.customElements; });
  fromInstance("DOMImplementation", function () { return doc.implementation; });
  fromInstance("Selection", function () { return selection; });
  fromInstance("CSSStyleDeclaration", function () { return null; });
  ["NamedNodeMap", "Attr", "StyleSheet", "CSSStyleSheet", "CSSRule", "MutationRecord", "DOMStringMap", "HTMLAllCollection",
   "CDATASection", "ProcessingInstruction", "StaticRange", "TextMetrics", "CanvasRenderingContext2D", "ImageBitmap",
   "TextTrack", "XMLHttpRequestUpload", "HTMLFormControlsCollection", "HTMLOptionsCollection"].forEach(function (n) {
    fromInstance(n, function () { return null; });
  });
  if (typeof g.DOMRect === "undefined") {
    var DOMRectReadOnly = class DOMRectReadOnly {
      constructor(x, y, w, h) { this.x = +x || 0; this.y = +y || 0; this.width = +w || 0; this.height = +h || 0; }
      get top() { return Math.min(this.y, this.y + this.height); }
      get bottom() { return Math.max(this.y, this.y + this.height); }
      get left() { return Math.min(this.x, this.x + this.width); }
      get right() { return Math.max(this.x, this.x + this.width); }
      toJSON() { return { x: this.x, y: this.y, width: this.width, height: this.height, top: this.top, right: this.right, bottom: this.bottom, left: this.left }; }
    };
    define("DOMRectReadOnly", DOMRectReadOnly);
    define("DOMRect", class DOMRect extends DOMRectReadOnly {});
    define("DOMPoint", class DOMPoint { constructor(x, y, z, w) { this.x = +x || 0; this.y = +y || 0; this.z = +z || 0; this.w = w === undefined ? 1 : +w; } });
  }
  if (typeof g.Blob === "undefined") {
    var utf8 = function (str) { return typeof g.TextEncoder === "function" ? new g.TextEncoder().encode(str) : Uint8Array.from(unescape(encodeURIComponent(str)), function (c) { return c.charCodeAt(0); }); };
    var Blob = class Blob {
      constructor(parts, opts) {
        var chunks = [], size = 0;
        (parts || []).forEach(function (part) {
          var b;
          if (part instanceof Blob) { b = part._b; }
          else if (part instanceof ArrayBuffer) { b = new Uint8Array(part.slice(0)); }
          else if (ArrayBuffer.isView(part)) { b = new Uint8Array(part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength)); }
          else { b = utf8(String(part)); }
          chunks.push(b); size += b.length;
        });
        var all = new Uint8Array(size), at = 0;
        chunks.forEach(function (b) { all.set(b, at); at += b.length; });
        this._b = all;
        this.type = opts && opts.type ? String(opts.type).toLowerCase() : "";
      }
      get size() { return this._b.length; }
      slice(a, b, type) { var out = new Blob([], { type: type || "" }); out._b = this._b.slice(a === undefined ? 0 : a, b === undefined ? this._b.length : b); return out; }
      arrayBuffer() { return Promise.resolve(this._b.buffer.slice(0)); }
      text() { var b = this._b; return Promise.resolve(typeof g.TextDecoder === "function" ? new g.TextDecoder().decode(b) : decodeURIComponent(escape(String.fromCharCode.apply(null, b)))); }
    };
    define("Blob", Blob);
    define("File", class File extends Blob {
      constructor(parts, name, opts) { super(parts, opts); this.name = String(name); this.lastModified = opts && opts.lastModified !== undefined ? +opts.lastModified : Date.now(); this.webkitRelativePath = ""; }
    });
    define("FileList", class FileList extends Array { item(i) { return this[i] || null; } });
    define("FileReader", class FileReader extends EventTarget {
      constructor() { super(); this.readyState = 0; this.result = null; this.error = null; }
      _read(blob, how) {
        var self = this; this.readyState = 1;
        var p = how === "buffer" ? blob.arrayBuffer() : how === "url" ? blob.arrayBuffer().then(function (ab) { var bin = "", u = new Uint8Array(ab); for (var i = 0; i < u.length; i++) { bin += String.fromCharCode(u[i]); } return "data:" + (blob.type || "application/octet-stream") + ";base64," + g.btoa(bin); }) : blob.text();
        p.then(function (v) {
          self.result = v; self.readyState = 2;
          ["load", "loadend"].forEach(function (t) { var ev = new Event(t); if (typeof self["on" + t] === "function") { try { self["on" + t](ev); } catch (e) { report(e); } } self.dispatchEvent(ev); });
        });
      }
      readAsText(b) { this._read(b, "text"); }
      readAsArrayBuffer(b) { this._read(b, "buffer"); }
      readAsDataURL(b) { this._read(b, "url"); }
      abort() {}
    });
  }
  if (typeof g.FormData === "undefined") {
    define("FormData", class FormData {
      constructor(form) {
        this._e = [];
        var self = this;
        if (form && form.nodeType === 1) {
          select(form, "input[name], select[name], textarea[name]", false).forEach(function (el) {
            var type = (el.getAttribute("type") || "").toLowerCase();
            if (el.hasAttribute("disabled") || type === "file" || type === "submit" || type === "button") { return; }
            if ((type === "checkbox" || type === "radio") && !el.checked) { return; }
            self._e.push([el.getAttribute("name"), String(el.value === undefined || el.value === null ? "" : el.value)]);
          });
        }
      }
      append(k, v) { this._e.push([String(k), v]); }
      set(k, v) { this.delete(k); this._e.push([String(k), v]); }
      delete(k) { k = String(k); this._e = this._e.filter(function (e) { return e[0] !== k; }); }
      get(k) { k = String(k); for (var i = 0; i < this._e.length; i++) { if (this._e[i][0] === k) { return this._e[i][1]; } } return null; }
      getAll(k) { k = String(k); return this._e.filter(function (e) { return e[0] === k; }).map(function (e) { return e[1]; }); }
      has(k) { return this.get(k) !== null; }
      forEach(fn, self) { this._e.forEach(function (e) { fn.call(self, e[1], e[0], this); }, this); }
      entries() { return this._e.map(function (e) { return [e[0], e[1]]; })[Symbol.iterator](); }
      keys() { return this._e.map(function (e) { return e[0]; })[Symbol.iterator](); }
      values() { return this._e.map(function (e) { return e[1]; })[Symbol.iterator](); }
      [Symbol.iterator]() { return this.entries(); }
    });
  }
  define("setImmediate", function (fn) { var a = Array.prototype.slice.call(arguments, 1); return g.setTimeout(function () { fn.apply(null, a); }, 0); });
  define("clearImmediate", function (id) { g.clearTimeout(id); });
  define("scroll", function () {});
  define("opener", null);
  define("CloseEvent", class CloseEvent extends Event { constructor(t, o) { super(t, o); o = o || {}; this.code = o.code || 0; this.reason = o.reason || ""; this.wasClean = !!o.wasClean; } });
  define("ToggleEvent", class ToggleEvent extends Event { constructor(t, o) { super(t, o); o = o || {}; this.oldState = o.oldState || ""; this.newState = o.newState || ""; } });

  var maskedToString = function toString() {
    if (natives.has(this)) { return "function " + (this.name || "") + "() { [native code] }"; }
    return realToString.call(this);
  };
  natives.add(maskedToString);
  function markNative(obj) {
    if (!obj) { return; }
    Object.getOwnPropertyNames(obj).forEach(function (name) {
      var d;
      try { d = Object.getOwnPropertyDescriptor(obj, name); } catch (_) { return; }
      if (!d) { return; }
      if (typeof d.value === "function") { natives.add(d.value); }
      if (typeof d.get === "function") { natives.add(d.get); }
      if (typeof d.set === "function") { natives.add(d.set); }
    });
  }
  for (k in exported) { if (typeof exported[k] === "function") { natives.add(exported[k]); markNative(exported[k]); markNative(exported[k].prototype); } }
  [g.Image, g.Audio, g.Option, g.DOMParser, g.XMLSerializer, g.getSelection, g.addEventListener, g.removeEventListener, g.dispatchEvent, doc.dispatchEvent, customElements.define, customElements.get, customElements.whenDefined, customElements.upgrade].forEach(function (f) { natives.add(f); });
  markNative(g.DOMParser.prototype); markNative(g.XMLSerializer.prototype);
  try { Object.defineProperty(Function.prototype, "toString", { value: maskedToString, writable: true, configurable: true }); } catch (_) {}

  // ── harness hooks ─────────────────────────────────────────────────────────
  var parsedScripts = null;
  g.__seLive = {
    // Called before each page script: find its element so currentScript and
    // document.write know where they are.
    enter: function (source, url) {
      if (!parsedScripts) { parsedScripts = select(doc, "script", false).filter(function (s) { return s._parsed; }); }
      var hit = null;
      for (var i = 0; i < parsedScripts.length; i++) {
        var s = parsedScripts[i];
        if (s._entered) { continue; }
        if (url ? (s._a.has("src") && resolveURL(s, s._a.get("src")) === url) : (!s._a.has("src") && s.textContent === source)) { hit = s; break; }
      }
      if (hit) { hit._entered = true; }
      currentScript = hit;
      writeAfter = null;
    },
    leave: function () { currentScript = null; writeAfter = null; },
    serialize: function () { var out = []; serialize(doc, out); return out.join(""); },
  };
  g.__seLiveFlush = function () { g.__seCommitHTML(g.__seLive.serialize()); };
})(globalThis);
