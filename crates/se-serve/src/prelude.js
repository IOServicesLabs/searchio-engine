// Render prelude (`prelude: true` on a render): the browser globals page
// bundles reach for before they draw anything, written in plain JS over what
// the bridge already provides. Every definition is guarded, so a global the
// bridge gains later wins over the one here. Runs once per render pass,
// before the page's first script.
(function (g) {
  "use strict";
  function def(name, value) {
    if (typeof g[name] === "undefined") {
      try { g[name] = value; } catch (e) {}
    }
  }

  // ── base64 ────────────────────────────────────────────────────────────────
  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  def("btoa", function btoa(input) {
    var s = String(input), out = "", i = 0;
    for (; i < s.length; i += 3) {
      var a = s.charCodeAt(i), b = s.charCodeAt(i + 1), c = s.charCodeAt(i + 2);
      if (a > 255 || b > 255 || c > 255) {
        throw new Error("InvalidCharacterError: btoa input outside Latin1");
      }
      var n = (a << 16) | ((b || 0) << 8) | (c || 0);
      out += B64.charAt(n >> 18) + B64.charAt((n >> 12) & 63) +
        (i + 1 < s.length ? B64.charAt((n >> 6) & 63) : "=") +
        (i + 2 < s.length ? B64.charAt(n & 63) : "=");
    }
    return out;
  });
  def("atob", function atob(input) {
    var s = String(input).replace(/[\t\n\f\r ]/g, "");
    if (s.length % 4 === 0) { s = s.replace(/==?$/, ""); }
    if (s.length % 4 === 1 || /[^A-Za-z0-9+\/]/.test(s)) {
      throw new Error("InvalidCharacterError: atob input is not base64");
    }
    var out = "", bits = 0, acc = 0;
    for (var i = 0; i < s.length; i++) {
      acc = (acc << 6) | B64.indexOf(s.charAt(i));
      bits += 6;
      if (bits >= 8) { bits -= 8; out += String.fromCharCode((acc >> bits) & 255); }
    }
    return out;
  });

  // ── URLSearchParams ───────────────────────────────────────────────────────
  function enc(s) {
    return encodeURIComponent(s).replace(/%20/g, "+").replace(/[!'()~]/g, function (c) {
      return "%" + c.charCodeAt(0).toString(16).toUpperCase();
    });
  }
  function dec(s) {
    try { return decodeURIComponent(String(s).replace(/\+/g, " ")); } catch (e) { return s; }
  }
  function Params(init) {
    this._l = [];
    this._url = null;
    var i;
    if (init == null || init === "") { return; }
    if (typeof init === "string") {
      var q = init.charAt(0) === "?" ? init.slice(1) : init;
      var parts = q.split("&");
      for (i = 0; i < parts.length; i++) {
        if (!parts[i]) { continue; }
        var eq = parts[i].indexOf("=");
        this._l.push(eq < 0 ? [dec(parts[i]), ""] : [dec(parts[i].slice(0, eq)), dec(parts[i].slice(eq + 1))]);
      }
    } else if (init instanceof Params) {
      this._l = init._l.map(function (p) { return [p[0], p[1]]; });
    } else if (Array.isArray(init)) {
      for (i = 0; i < init.length; i++) { this._l.push([String(init[i][0]), String(init[i][1])]); }
    } else {
      for (var k in init) {
        if (Object.prototype.hasOwnProperty.call(init, k)) { this._l.push([k, String(init[k])]); }
      }
    }
  }
  Params.prototype = {
    constructor: Params,
    _sync: function () { if (this._url) { this._url._setSearch(this.toString()); } },
    append: function (k, v) { this._l.push([String(k), String(v)]); this._sync(); },
    "delete": function (k) { this._l = this._l.filter(function (p) { return p[0] !== String(k); }); this._sync(); },
    get: function (k) {
      for (var i = 0; i < this._l.length; i++) { if (this._l[i][0] === String(k)) { return this._l[i][1]; } }
      return null;
    },
    getAll: function (k) {
      return this._l.filter(function (p) { return p[0] === String(k); }).map(function (p) { return p[1]; });
    },
    has: function (k) { return this.get(k) !== null; },
    set: function (k, v) {
      k = String(k); v = String(v);
      var done = false;
      this._l = this._l.filter(function (p) {
        if (p[0] !== k) { return true; }
        if (done) { return false; }
        p[1] = v; done = true; return true;
      });
      if (!done) { this._l.push([k, v]); }
      this._sync();
    },
    sort: function () { this._l.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; }); this._sync(); },
    forEach: function (fn, self) { this._l.forEach(function (p) { fn.call(self, p[1], p[0], this); }, this); },
    keys: function () { return this._l.map(function (p) { return p[0]; })[Symbol.iterator](); },
    values: function () { return this._l.map(function (p) { return p[1]; })[Symbol.iterator](); },
    entries: function () { return this._l.map(function (p) { return [p[0], p[1]]; })[Symbol.iterator](); },
    toString: function () { return this._l.map(function (p) { return enc(p[0]) + "=" + enc(p[1]); }).join("&"); }
  };
  Params.prototype[Symbol.iterator] = Params.prototype.entries;
  Object.defineProperty(Params.prototype, "size", { get: function () { return this._l.length; } });
  def("URLSearchParams", Params);

  // ── URL ───────────────────────────────────────────────────────────────────
  var PORTS = { "http:": "80", "https:": "443", "ws:": "80", "wss:": "443", "ftp:": "21" };
  var ABS = /^([a-zA-Z][a-zA-Z0-9+.\-]*:)(?:\/\/(?:([^\/?#@]*)@)?(\[[^\]]*\]|[^\/?#:]*)(?::(\d*))?)?([^?#]*)(\?[^#]*)?(#.*)?$/;
  function normPath(path) {
    var out = [], segs = path.split("/");
    for (var i = 0; i < segs.length; i++) {
      var s = segs[i];
      if (s === "..") { if (out.length > 1) { out.pop(); } if (i === segs.length - 1) { out.push(""); } }
      else if (s === ".") { if (i === segs.length - 1) { out.push(""); } }
      else { out.push(s); }
    }
    var p = out.join("/");
    return p.charAt(0) === "/" ? p : "/" + p;
  }
  function URLp(input, base) {
    input = String(input).trim();
    var m = ABS.exec(input);
    var special = m && /^(https?|wss?|ftp|file):$/i.test(m[1]);
    if (!m || (special && input.slice(m[1].length, m[1].length + 2) !== "//" && base !== undefined)) { m = null; }
    if (!m) {
      if (base === undefined) { throw new TypeError("Invalid URL: " + input); }
      var b = base instanceof URLp ? base : new URLp(String(base));
      var abs;
      if (input.slice(0, 2) === "//") { abs = b.protocol + input; }
      else if (input.charAt(0) === "/") { abs = b.origin + input; }
      else if (input.charAt(0) === "?") { abs = b.origin + b.pathname + input; }
      else if (input.charAt(0) === "#") { abs = b.origin + b.pathname + b.search + input; }
      else if (input === "") { abs = b.origin + b.pathname + b.search; }
      else { abs = b.origin + b.pathname.replace(/[^\/]*$/, "") + input; }
      m = ABS.exec(abs);
      if (!m) { throw new TypeError("Invalid URL: " + input); }
    }
    this.protocol = m[1].toLowerCase();
    var auth = (m[2] || "").split(":");
    this.username = auth[0] || "";
    this.password = auth.length > 1 ? auth.slice(1).join(":") : "";
    this.hostname = (m[3] || "").toLowerCase();
    this.port = m[4] && m[4] !== PORTS[this.protocol] ? m[4] : "";
    var hier = PORTS[this.protocol] !== undefined || this.protocol === "file:";
    this.pathname = hier ? normPath(m[5] || "/") : (m[5] || "");
    this._search = m[6] && m[6] !== "?" ? m[6] : "";
    this.hash = m[7] && m[7] !== "#" ? m[7] : "";
    this.searchParams = new Params(this._search);
    this.searchParams._url = this;
  }
  URLp.prototype = {
    constructor: URLp,
    _setSearch: function (q) { this._search = q ? "?" + q : ""; },
    toString: function () { return this.href; },
    toJSON: function () { return this.href; }
  };
  Object.defineProperties(URLp.prototype, {
    host: { get: function () { return this.hostname + (this.port ? ":" + this.port : ""); } },
    origin: {
      get: function () {
        return PORTS[this.protocol] !== undefined ? this.protocol + "//" + this.host : "null";
      }
    },
    search: {
      get: function () { return this._search; },
      set: function (v) {
        v = String(v);
        this._search = v && v !== "?" ? (v.charAt(0) === "?" ? v : "?" + v) : "";
        this.searchParams._l = new Params(this._search)._l;
      }
    },
    href: {
      get: function () {
        var auth = this.username ? this.username + (this.password ? ":" + this.password : "") + "@" : "";
        var slashes = PORTS[this.protocol] !== undefined || this.protocol === "file:" || this.hostname ? "//" : "";
        return this.protocol + slashes + auth + this.host + this.pathname + this._search + this.hash;
      }
    }
  });
  URLp.canParse = function (u, b) { try { new URLp(u, b); return true; } catch (e) { return false; } };
  def("URL", URLp);

  // ── Headers ───────────────────────────────────────────────────────────────
  function Hdrs(init) {
    this._m = {};
    var self = this;
    if (!init) { return; }
    if (typeof init.forEach === "function" && !Array.isArray(init)) {
      init.forEach(function (v, k) { self.append(k, v); });
    } else if (Array.isArray(init)) {
      init.forEach(function (p) { self.append(p[0], p[1]); });
    } else {
      Object.keys(init).forEach(function (k) { self.append(k, init[k]); });
    }
  }
  Hdrs.prototype = {
    constructor: Hdrs,
    append: function (k, v) {
      k = String(k).toLowerCase();
      this._m[k] = k in this._m ? this._m[k] + ", " + v : String(v);
    },
    set: function (k, v) { this._m[String(k).toLowerCase()] = String(v); },
    get: function (k) { k = String(k).toLowerCase(); return k in this._m ? this._m[k] : null; },
    has: function (k) { return String(k).toLowerCase() in this._m; },
    "delete": function (k) { delete this._m[String(k).toLowerCase()]; },
    forEach: function (fn, self) {
      Object.keys(this._m).sort().forEach(function (k) { fn.call(self, this._m[k], k, this); }, this);
    },
    keys: function () { return Object.keys(this._m).sort()[Symbol.iterator](); },
    values: function () { var m = this._m; return Object.keys(m).sort().map(function (k) { return m[k]; })[Symbol.iterator](); },
    entries: function () { var m = this._m; return Object.keys(m).sort().map(function (k) { return [k, m[k]]; })[Symbol.iterator](); }
  };
  Hdrs.prototype[Symbol.iterator] = Hdrs.prototype.entries;
  def("Headers", Hdrs);

  // ── EventTarget (for the objects defined here) ────────────────────────────
  function Target() { this._ls = {}; }
  Target.prototype.addEventListener = function (type, fn) {
    if (typeof fn !== "function" && !(fn && typeof fn.handleEvent === "function")) { return; }
    (this._ls[type] = this._ls[type] || []).push(fn);
  };
  Target.prototype.removeEventListener = function (type, fn) {
    this._ls[type] = (this._ls[type] || []).filter(function (f) { return f !== fn; });
  };
  Target.prototype.dispatchEvent = function (ev) {
    if (!ev.target) { try { ev.target = this; ev.currentTarget = this; } catch (e) {} }
    var on = this["on" + ev.type];
    if (typeof on === "function") { try { on.call(this, ev); } catch (e1) { report(e1); } }
    (this._ls[ev.type] || []).slice().forEach(function (fn) {
      try { typeof fn === "function" ? fn.call(this, ev) : fn.handleEvent(ev); } catch (e2) { report(e2); }
    }, this);
    return true;
  };
  def("EventTarget", Target);
  function report(e) {
    try { (g.__sePageErrors = g.__sePageErrors || []).push(String(e && e.stack || e).slice(0, 300)); } catch (x) {}
  }
  g.__sePageErrors = g.__sePageErrors || [];

  // ── scheduling ────────────────────────────────────────────────────────────
  def("requestIdleCallback", function requestIdleCallback(fn) {
    return setTimeout(function () {
      fn({ didTimeout: false, timeRemaining: function () { return 50; } });
    }, 1);
  });
  def("cancelIdleCallback", function cancelIdleCallback(id) { clearTimeout(id); });
  if (typeof g.MessageChannel === "undefined") {
    var Port = function () { Target.call(this); this._other = null; this.onmessage = null; };
    Port.prototype = Object.create(Target.prototype);
    Port.prototype.postMessage = function (data) {
      var other = this._other;
      if (!other) { return; }
      setTimeout(function () { other.dispatchEvent({ type: "message", data: data, target: other }); }, 0);
    };
    Port.prototype.start = function () {};
    Port.prototype.close = function () { this._other = null; };
    g.MessagePort = Port;
    g.MessageChannel = function MessageChannel() {
      this.port1 = new Port(); this.port2 = new Port();
      this.port1._other = this.port2; this.port2._other = this.port1;
    };
  }

  // ── XMLHttpRequest with events ────────────────────────────────────────────
  // The bridge's XHR completes inside send() and fires no event, so a page
  // that waits on onload / onreadystatechange (axios, jQuery, most hand
  // written loaders) never hears back. This one rides fetch() and reports
  // the way a browser does.
  var NativeXHR = g.XMLHttpRequest;
  var probe = null;
  try { probe = NativeXHR ? new NativeXHR() : null; } catch (e) {}
  if (typeof g.fetch === "function" && (!probe || typeof probe.addEventListener !== "function")) {
    var XHR = function XMLHttpRequest() {
      Target.call(this);
      this.readyState = 0; this.status = 0; this.statusText = "";
      this.responseText = ""; this.response = ""; this.responseType = "";
      this.responseURL = ""; this.timeout = 0; this.withCredentials = false;
      this.upload = new Target();
      this._h = {}; this._rh = null; this._sent = false; this._aborted = false;
    };
    XHR.prototype = Object.create(Target.prototype);
    XHR.prototype.constructor = XHR;
    XHR.UNSENT = 0; XHR.OPENED = 1; XHR.HEADERS_RECEIVED = 2; XHR.LOADING = 3; XHR.DONE = 4;
    XHR.prototype.UNSENT = 0; XHR.prototype.OPENED = 1; XHR.prototype.HEADERS_RECEIVED = 2;
    XHR.prototype.LOADING = 3; XHR.prototype.DONE = 4;
    XHR.prototype._state = function (n) {
      this.readyState = n;
      this.dispatchEvent({ type: "readystatechange" });
    };
    XHR.prototype.open = function (method, url) {
      this._method = String(method || "GET").toUpperCase();
      this._url = String(url);
      this._h = {}; this._sent = false; this._aborted = false;
      this._state(1);
    };
    XHR.prototype.setRequestHeader = function (k, v) {
      this._h[k] = k in this._h ? this._h[k] + ", " + v : String(v);
    };
    XHR.prototype.overrideMimeType = function () {};
    XHR.prototype.getResponseHeader = function (k) {
      return this._rh && typeof this._rh.get === "function" ? this._rh.get(k) : null;
    };
    XHR.prototype.getAllResponseHeaders = function () {
      var out = "";
      if (this._rh && typeof this._rh.forEach === "function") {
        this._rh.forEach(function (v, k) { out += k + ": " + v + "\r\n"; });
      }
      return out;
    };
    XHR.prototype.abort = function () {
      this._aborted = true;
      if (this._sent && this.readyState !== 4) {
        this.readyState = 4;
        this.dispatchEvent({ type: "abort" });
        this.dispatchEvent({ type: "loadend" });
      }
      this.readyState = 0;
    };
    XHR.prototype.send = function (body) {
      var x = this;
      if (x.readyState !== 1 || x._sent) { throw new Error("InvalidStateError: XMLHttpRequest.send"); }
      x._sent = true;
      var init = { method: x._method, headers: x._h };
      if (body != null && x._method !== "GET" && x._method !== "HEAD") {
        init.body = typeof body === "string" ? body : String(body);
      }
      x.dispatchEvent({ type: "loadstart" });
      var fail = function (kind) {
        if (x._aborted) { return; }
        x.status = 0; x.readyState = 4;
        x.dispatchEvent({ type: "readystatechange" });
        x.dispatchEvent({ type: kind });
        x.dispatchEvent({ type: "loadend" });
      };
      var p;
      try { p = g.fetch(x._url, init); } catch (e) { setTimeout(function () { fail("error"); }, 0); return; }
      p.then(function (r) {
        if (x._aborted) { return; }
        x.status = r.status; x.statusText = r.statusText || "";
        x.responseURL = r.url || x._url; x._rh = r.headers || null;
        x._state(2);
        return r.text().then(function (t) {
          if (x._aborted) { return; }
          x._state(3);
          x.responseText = t;
          if (x.responseType === "json") {
            try { x.response = JSON.parse(t); } catch (e) { x.response = null; }
          } else { x.response = t; }
          x._state(4);
          var ev = { type: "load", loaded: t.length, total: t.length, lengthComputable: true };
          x.dispatchEvent(ev);
          x.dispatchEvent({ type: "loadend", loaded: t.length, total: t.length });
        });
      }, function () { fail("error"); });
    };
    g.XMLHttpRequest = XHR;
  }

  // ── document conveniences ─────────────────────────────────────────────────
  var d = g.document;
  if (d) {
    var lazy = function (name, get) {
      try {
        if (d[name] === undefined) {
          Object.defineProperty(d, name, { get: get, configurable: true });
        }
      } catch (e) {}
    };
    lazy("head", function () { return d.querySelector("head"); });
    lazy("defaultView", function () { return g; });
    lazy("scripts", function () { return d.querySelectorAll("script"); });
    lazy("currentScript", function () { return null; });
    lazy("styleSheets", function () { return []; });
    if (typeof d.getElementsByTagName !== "function") {
      d.getElementsByTagName = function (t) { return d.querySelectorAll(String(t)); };
    }
    if (typeof d.getElementsByClassName !== "function") {
      d.getElementsByClassName = function (c) {
        return d.querySelectorAll("." + String(c).trim().split(/\s+/).join("."));
      };
    }
    if (typeof d.createEvent !== "function") {
      d.createEvent = function () {
        var ev = { type: "", bubbles: false, cancelable: false };
        ev.initEvent = ev.initCustomEvent = function (t, b, c, detail) {
          ev.type = t; ev.bubbles = !!b; ev.cancelable = !!c; ev.detail = detail;
        };
        return ev;
      };
    }
  }
  def("devicePixelRatio", 1);
  def("top", g); def("parent", g); def("frames", g);

  // ── errors a page reports to itself ───────────────────────────────────────
  if (g.console && typeof g.console.error === "function" && !g.console.__seWrapped) {
    var realError = g.console.error;
    g.console.error = function () {
      try { report(Array.prototype.slice.call(arguments).map(String).join(" ")); } catch (e) {}
      return realError.apply(g.console, arguments);
    };
    g.console.__seWrapped = true;
  }
  if (typeof g.addEventListener === "function") {
    try {
      g.addEventListener("unhandledrejection", function (ev) {
        report("unhandled rejection: " + (ev && ev.reason));
      });
    } catch (e) {}
  }
})(globalThis);
