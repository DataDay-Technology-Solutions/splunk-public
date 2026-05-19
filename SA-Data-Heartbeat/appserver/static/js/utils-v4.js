/**
 * SA-Data-Heartbeat - Shared utilities
 *
 * Centralizes Toast notifications, string escaping, and localStorage
 * helpers so they're not duplicated across heartbeat.js / settings.js / audit.js.
 *
 * Exposed as window.HeartbeatUtils.
 */

require([
    'jquery',
    'underscore'
], function ($, _) {
    'use strict';

    // SPL string escaping. Handles single-quote, double-quote, backslash,
    // and control characters that could break SPL composition or audit logs.
    function escapeString(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/\\/g, '\\\\')
            .replace(/"/g, '\\"')
            .replace(/'/g, "\\'")
            .replace(/\r/g, '\\r')
            .replace(/\n/g, '\\n')
            .replace(/\t/g, '\\t');
    }

    // Strip HTML for safe rendering (defense-in-depth; jQuery .text() should be primary)
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    var Toast = (function () {
        var $container = null;

        function ensureContainer() {
            if ($container && $container.length) return $container;
            $container = $('#hb-toast-container');
            if (!$container.length) {
                $container = $('<div id="hb-toast-container" aria-live="polite" aria-atomic="true"></div>');
                $('body').append($container);
            }
            return $container;
        }

        function show(message, type, durationMs, action) {
            ensureContainer();
            type = type || 'info';
            durationMs = typeof durationMs === 'number' ? durationMs : 4000;

            var $toast = $('<div></div>')
                .addClass('hb-toast hb-toast-' + type)
                .attr('role', type === 'error' ? 'alert' : 'status');
            $toast.append($('<span></span>').text(message));
            if (action && action.label && action.href) {
                var $a = $('<a></a>')
                    .attr('href', action.href)
                    .attr('target', '_blank')
                    .attr('rel', 'noopener')
                    .addClass('hb-toast-action')
                    .text(action.label);
                $toast.append(' ').append($a);
            }

            $container.append($toast);
            window.requestAnimationFrame(function () {
                $toast.addClass('hb-toast-visible');
            });

            window.setTimeout(function () {
                $toast.removeClass('hb-toast-visible');
                window.setTimeout(function () { $toast.remove(); }, 400);
            }, durationMs);
        }

        return {
            success: function (m, d) { show(m, 'success', d); },
            error: function (m, d, action) { show(m, 'error', d || 8000, action); },
            warning: function (m, d) { show(m, 'warning', d); },
            info: function (m, d) { show(m, 'info', d); }
        };
    })();

    // Namespaced localStorage with safe JSON. Falls back silently if storage unavailable.
    var Storage = (function () {
        var PREFIX = 'sa_heartbeat:';
        function safeGet(key) {
            try {
                var raw = window.localStorage.getItem(PREFIX + key);
                if (raw === null) return null;
                return JSON.parse(raw);
            } catch (e) { return null; }
        }
        function safeSet(key, value) {
            try {
                window.localStorage.setItem(PREFIX + key, JSON.stringify(value));
                return true;
            } catch (e) { return false; }
        }
        function safeRemove(key) {
            try { window.localStorage.removeItem(PREFIX + key); return true; }
            catch (e) { return false; }
        }
        return { get: safeGet, set: safeSet, remove: safeRemove };
    })();

    // Debounce: returns a wrapper that delays invoking fn until `wait` ms
    // have elapsed since the last call. Use for filter inputs, search-as-you-type.
    function debounce(fn, wait) {
        var timer = null;
        return function() {
            var ctx = this;
            var args = arguments;
            window.clearTimeout(timer);
            timer = window.setTimeout(function() { fn.apply(ctx, args); }, wait || 200);
        };
    }

    // FocusTrap: keyboard accessibility helper for modals.
    // Activate when modal opens; deactivate when it closes.
    // Esc key triggers onEscape callback.
    var FocusTrap = (function () {
        var active = null; // { container, previouslyFocused, onEscape, handler }

        function focusableElements($container) {
            return $container.find(
                'a[href], button:not([disabled]), textarea:not([disabled]),' +
                ' input:not([disabled]):not([type="hidden"]), select:not([disabled]),' +
                ' [tabindex]:not([tabindex="-1"])'
            ).filter(':visible');
        }

        function activate($container, opts) {
            opts = opts || {};
            deactivate(); // only one trap at a time
            var prev = document.activeElement;
            var $focusable = focusableElements($container);
            if ($focusable.length) $focusable.first().focus();

            function handler(e) {
                if (e.key === 'Escape') {
                    e.preventDefault();
                    if (typeof opts.onEscape === 'function') opts.onEscape(e);
                    return;
                }
                if (e.key !== 'Tab') return;
                var $els = focusableElements($container);
                if (!$els.length) return;
                var first = $els[0];
                var last = $els[$els.length - 1];
                if (e.shiftKey && document.activeElement === first) {
                    e.preventDefault();
                    last.focus();
                } else if (!e.shiftKey && document.activeElement === last) {
                    e.preventDefault();
                    first.focus();
                }
            }
            document.addEventListener('keydown', handler, true);
            active = { container: $container, previouslyFocused: prev, onEscape: opts.onEscape, handler: handler };
        }

        function deactivate() {
            if (!active) return;
            document.removeEventListener('keydown', active.handler, true);
            try { if (active.previouslyFocused && active.previouslyFocused.focus) active.previouslyFocused.focus(); } catch (e) {}
            active = null;
        }

        return { activate: activate, deactivate: deactivate };
    })();

    // Permissions: query Splunk REST for the current user's roles.
    // Caches result. Resolves with { username, roles, isAdmin, canWrite }.
    var Permissions = (function () {
        var cached = null;
        var inflight = null;
        function load() {
            if (cached) return $.Deferred().resolve(cached).promise();
            if (inflight) return inflight;
            inflight = $.ajax({
                url: '/en-US/splunkd/__raw/services/authentication/current-context?output_mode=json',
                method: 'GET',
                cache: false
            }).then(function (data) {
                var entry = (data && data.entry && data.entry[0]) || {};
                var content = entry.content || {};
                var roles = content.roles || [];
                var username = entry.name || content.username || 'unknown';
                var isAdmin = roles.indexOf('admin') !== -1 || roles.indexOf('sc_admin') !== -1;
                cached = { username: username, roles: roles, isAdmin: isAdmin, canWrite: isAdmin };
                inflight = null;
                return cached;
            }, function () {
                inflight = null;
                cached = { username: 'unknown', roles: [], isAdmin: false, canWrite: false };
                return cached;
            });
            return inflight;
        }
        return { load: load, get: function () { return cached; } };
    })();

    // Keyboard shortcut registry. Each shortcut: { key, handler, description, scope }.
    // Default scope filters out shortcuts when focused on form fields, so typing
    // doesn't accidentally trigger refresh/discover.
    var Shortcuts = (function () {
        var registry = [];
        function isTypingTarget(t) {
            if (!t) return false;
            var tag = (t.tagName || '').toLowerCase();
            return tag === 'input' || tag === 'textarea' || tag === 'select' || t.isContentEditable;
        }
        function register(spec) {
            if (!spec || !spec.key || typeof spec.handler !== 'function') return;
            registry.push(spec);
        }
        function help() {
            return registry.map(function (s) {
                return { key: s.key, description: s.description || '' };
            });
        }
        document.addEventListener('keydown', function (e) {
            // Ignore auto-repeats from key-hold — otherwise holding `r` spams
            // refreshData() many times per second and floods splunkd.
            if (e.repeat) return;
            if (isTypingTarget(e.target)) return;
            registry.forEach(function (s) {
                if (e.key === s.key && !e.ctrlKey && !e.metaKey && !e.altKey) {
                    e.preventDefault();
                    s.handler(e);
                }
            });
        });
        return { register: register, help: help };
    })();

    window.HeartbeatUtils = {
        escapeString: escapeString,
        escapeHtml: escapeHtml,
        Toast: Toast,
        Storage: Storage,
        debounce: debounce,
        FocusTrap: FocusTrap,
        Permissions: Permissions,
        Shortcuts: Shortcuts
    };

    // Eagerly load permissions so the UI can hide write controls early.
    Permissions.load();
});
