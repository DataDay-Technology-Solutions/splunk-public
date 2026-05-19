/**
 * SA-Data-Heartbeat - Main JavaScript
 * Handles state management and UI interactions
 */

require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/utils',
    'splunkjs/mvc/simplexml/ready!'
], function($, _, mvc, SearchManager, utils) {
    'use strict';

    var APP_NAME = 'SA-Data-Heartbeat';
    // CSV-backed lookup. sourcetype acts as the natural primary key (we set
    // _key=sourcetype on writes and dedup before outputlookup). KV-store
    // collection is defined in collections.conf for future use, but the
    // runtime path stays on CSV for simpler ops + no MongoDB dependency.
    // Primary store: KV-store-backed lookup (see transforms.conf +
    // collections.conf). KV gives us document-level locking, SH cluster
    // replication, and per-row REST PUT/DELETE — all CSV can't do.
    // CSV (monitored_sourcetypes.csv) is shipped as the cold-start seed
    // and as a nightly backup target.
    var LOOKUP_FILE = 'monitored_sourcetypes_lookup';
    var LOOKUP_FILE_CSV = 'monitored_sourcetypes_csv'; // fallback / seed source

    // HTML escape — prevents XSS when stored sourcetype names or notes
    // contain markup. Used everywhere user-controlled strings get spliced
    // into innerHTML via string concatenation in the table render.
    function esc(s) {
        if (s === null || s === undefined) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
    var SETTINGS_FILE = 'heartbeat_settings.csv';
    var AUDIT_LOG_FILE = 'heartbeat_audit_log.csv';
    var ALERT_ACTIONS_FILE = 'heartbeat_alert_actions.csv';

    // Sourcetype-monitoring scale limits. Each monitored sourcetype runs a
    // recurring detection search, so cardinality has real cost — at scale,
    // both the scheduled-search load and the dashboard render time degrade.
    //   SOFT — confirm with the user before crossing this.
    //   HARD — block entirely. Most installs can't keep up beyond this.
    var SOFT_LIMIT_SOURCETYPES = 500;
    var HARD_LIMIT_SOURCETYPES = 1000;

    // Auto-poll cadence for the Monitor table (no more Refresh button).
    var AUTO_POLL_MS = 30000;

    // Track current user
    var currentUser = Splunk.util.getConfigValue('USERNAME') || 'admin';

    // Store configured alert actions loaded from Settings
    var configuredAlertActions = {};

    // Pagination state — pageSize persists across reloads via localStorage
    var DEFAULT_PAGE_SIZE = 25;
    var pageSize = (function() {
        try {
            var v = parseInt(window.localStorage.getItem('sa_heartbeat:page_size') || '', 10);
            return [10, 25, 50, 100].indexOf(v) !== -1 ? v : DEFAULT_PAGE_SIZE;
        } catch (e) { return DEFAULT_PAGE_SIZE; }
    })();
    var currentPage = 1;

    // Hardened SPL string escape — handles backslash, quotes, and control chars
    // that could break SPL composition or audit logs.
    function escapeStr(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/\\/g, '\\\\')
            .replace(/"/g, '\\"')
            .replace(/'/g, "\\'")
            .replace(/\r/g, '\\r')
            .replace(/\n/g, '\\n')
            .replace(/\t/g, '\\t');
    }

    // Namespaced localStorage helper — silently no-ops if storage unavailable
    var FilterStorage = {
        KEY: 'sa_heartbeat:monitor_filters',
        load: function() {
            try {
                var raw = window.localStorage.getItem(this.KEY);
                if (!raw) return null;
                var parsed = JSON.parse(raw);
                return (parsed && typeof parsed === 'object') ? parsed : null;
            } catch (e) { return null; }
        },
        save: function(filters) {
            try { window.localStorage.setItem(this.KEY, JSON.stringify(filters)); } catch (e) {}
        }
    };

    // Current filter state — restored from localStorage if present
    var currentFilters = (function() {
        var saved = FilterStorage.load();
        return {
            status: (saved && saved.status) || 'all',
            importance: (saved && saved.importance) || 'all'
        };
    })();

    // ========================================
    // Audit Logger
    // ========================================
    var AuditLogger = {
        log: function(action, sourcetype, previousValue, newValue, details, callback) {
            var timestamp = Math.floor(Date.now() / 1000);
            var query = '| inputlookup ' + AUDIT_LOG_FILE +
                ' | append [| makeresults' +
                ' | eval timestamp=' + timestamp +
                ', action="' + this.escapeString(action) + '"' +
                ', sourcetype="' + this.escapeString(sourcetype || '') + '"' +
                ', performed_by="' + this.escapeString(currentUser) + '"' +
                ', previous_value="' + this.escapeString(previousValue || '') + '"' +
                ', new_value="' + this.escapeString(newValue || '') + '"' +
                ', details="' + this.escapeString(details || '') + '"' +
                ' | fields - _time]' +
                ' | outputlookup ' + AUDIT_LOG_FILE;

            var searchId = 'audit_log_' + Date.now();
            var settled = false;
            function done(err) {
                if (settled) return;
                settled = true;
                try { sm.cancel(); } catch (e) {}
                if (callback) callback(err);
            }
            var sm = new SearchManager({
                id: searchId,
                search: query,
                earliest_time: '-24h',
                latest_time: 'now',
                preview: false,
                cache: false,
                autostart: true
            }, { tokens: true });

            sm.on('search:done',  function()    { done(null); });
            sm.on('search:error', function(err) { console.error('Audit log error:', err); done(err); });
            sm.on('search:fail',  function(err) { done(err || new Error('audit log search failed')); });
            // Watchdog: prevents the search from hanging forever if splunkd
            // never fires done/error/fail (happens occasionally on overloaded
            // search heads). 30s is plenty for an audit log write.
            window.setTimeout(function () {
                if (!settled) done(new Error('audit log timed out'));
            }, 30000);
        },

        escapeString: escapeStr
    };

    // Toast comes from HeartbeatUtils (loaded by js/utils.js).
    // Fallback shim if utils.js failed to load — keeps the page functional.
    var Toast = (window.HeartbeatUtils && window.HeartbeatUtils.Toast) || {
        success: function(m) { console.log('[toast/success]', m); },
        error:   function(m) { console.error('[toast/error]', m); },
        warning: function(m) { console.warn('[toast/warning]', m); },
        info:    function(m) { console.info('[toast/info]', m); },
        show:    function(m, t) { console.log('[toast/' + (t || 'info') + ']', m); }
    };

    // ========================================
    // Lookup Management
    // ========================================
    var LookupManager = {
        runSearch: function(query, callback) {
            var searchId = 'hb_search_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
            var settled = false;
            function done(err, rows) {
                if (settled) return;
                settled = true;
                try { sm.cancel(); } catch (e) {}
                if (callback) callback(err, rows);
            }

            var sm = new SearchManager({
                id: searchId,
                search: query,
                earliest_time: '-24h',
                latest_time: 'now',
                preview: false,
                cache: false,
                autostart: true
            }, { tokens: true });

            sm.on('search:done', function(properties) {
                // Short-circuit on empty result sets — the 'data' event on the
                // results model does not fire when resultCount === 0, which
                // would otherwise hang the dashboard forever (v1.2.0 regression
                // exposed by the now-empty default monitored_sourcetypes.csv).
                var resultCount = (properties && properties.content && properties.content.resultCount) || 0;
                if (resultCount === 0) {
                    done(null, []);
                    return;
                }
                var results = sm.data('results', { output_mode: 'json', count: 0 });
                results.on('data', function() {
                    var rows = (results.data() && results.data().results) || [];
                    done(null, rows);
                });
                results.on('error', function(err) {
                    done(err);
                });
            });

            sm.on('search:error', function(err) {
                done(err);
            });

            sm.on('search:fail', function(err) {
                done(err || new Error('search failed'));
            });

            // Watchdog: a search that never fires done/error within 60s is hung.
            // Surface it instead of letting the spinner spin forever.
            window.setTimeout(function() {
                if (!settled) done(new Error('Search timed out after 60s'));
            }, 60000);
        },

        getSourceTypes: function(callback) {
            var query = '| inputlookup ' + LOOKUP_FILE;
            this.runSearch(query, callback);
        },

        getSettings: function(callback) {
            var query = '| inputlookup ' + SETTINGS_FILE;
            this.runSearch(query, callback);
        },

        addSourceType: function(sourcetype, threshold, importance, notes, callback) {
            var now = Math.floor(Date.now() / 1000);

            // Auto-classify if user didn't specify importance or used default
            // Never auto-assign VIP - only users can do that
            var finalImportance = importance || 'high';
            var finalThreshold = parseInt(threshold, 10) || 60;
            var finalNotes = notes || '';

            // If using defaults, check if we can auto-classify (catalog can elevate to vip/critical)
            if (!importance || importance === 'medium' || importance === 'high') {
                var classification = SourceTypeClassifier.classify(sourcetype);
                if (classification) {
                    finalImportance = classification.importance;
                    finalThreshold = classification.threshold;
                    if (!notes) {
                        finalNotes = classification.notes + ' (auto-classified)';
                    }
                }
            }

            var query = '| inputlookup ' + LOOKUP_FILE +
                ' | append [| makeresults' +
                ' | eval sourcetype="' + this.escapeString(sourcetype) + '"' +
                ', threshold_minutes=' + finalThreshold +
                ', last_seen=0' +
                ', minutes_since_seen=0' +
                ', status="pending"' +
                ', importance="' + this.escapeString(finalImportance) + '"' +
                ', discovery_source="manual"' +
                ', usage_count=0' +
                ', added_by="' + this.escapeString(currentUser) + '"' +
                ', added_time=' + now +
                ', notes="' + this.escapeString(finalNotes) + '"' +
                ' | fields - _time]' +
                ' | dedup sourcetype' +
                ' | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

            this.runSearch(query, callback);
        },

        removeSourceType: function(sourcetype, callback) {
            var query = '| inputlookup ' + LOOKUP_FILE +
                ' | where sourcetype!="' + this.escapeString(sourcetype) + '"' +
                ' | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

            this.runSearch(query, callback);
        },

        updateThreshold: function(sourcetype, threshold, callback) {
            // Update threshold AND recalculate status in one operation.
            //
            // Range-check before interpolation: parseInt of a non-numeric or
            // empty value returns NaN, which would write the literal string
            // "NaN" into KV and silently break status calc on every later
            // Detection run (`tonumber("NaN") = null`). Clamp to [1, 525600]
            // (one year) and bail with an error if the input is unusable.
            var thresholdVal = parseInt(threshold, 10);
            if (isNaN(thresholdVal) || thresholdVal < 1) {
                if (callback) callback(new Error('Invalid threshold: ' + threshold));
                return;
            }
            if (thresholdVal > 525600) thresholdVal = 525600;
            var query = '| inputlookup ' + LOOKUP_FILE +
                ' | eval threshold_minutes=if(sourcetype="' + this.escapeString(sourcetype) + '", ' + thresholdVal + ', threshold_minutes)' +
                ' | eval status=if(sourcetype="' + this.escapeString(sourcetype) + '", if(minutes_since_seen > ' + thresholdVal + ' OR last_seen = 0, "flagged", "good"), status)' +
                ' | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

            this.runSearch(query, callback);
        },

        updateImportance: function(sourcetype, importance, callback) {
            var query = '| inputlookup ' + LOOKUP_FILE +
                ' | eval importance=if(sourcetype="' + this.escapeString(sourcetype) + '", "' + this.escapeString(importance) + '", importance)' +
                ' | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

            this.runSearch(query, callback);
        },

        updateAlertAction: function(sourcetype, action, config, callback) {
            var query = '| inputlookup ' + LOOKUP_FILE +
                ' | eval alert_action=if(sourcetype="' + this.escapeString(sourcetype) + '", "' + this.escapeString(action) + '", alert_action)' +
                ' | eval alert_action_config=if(sourcetype="' + this.escapeString(sourcetype) + '", "' + this.escapeString(config) + '", alert_action_config)' +
                ' | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

            this.runSearch(query, callback);
        },

        updateNotes: function(sourcetype, notes, callback) {
            var query = '| inputlookup ' + LOOKUP_FILE +
                ' | eval notes=if(sourcetype="' + this.escapeString(sourcetype) + '", "' + this.escapeString(notes) + '", notes)' +
                ' | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

            this.runSearch(query, callback);
        },

        escapeString: escapeStr
    };

    // ========================================
    // Alert Actions Configuration Manager
    // Loads configured actions from Settings page
    // ========================================
    var AlertActionsConfigManager = {
        loadConfiguredActions: function(callback) {
            var query = '| inputlookup ' + ALERT_ACTIONS_FILE + ' | table action_type, enabled, config_json';
            LookupManager.runSearch(query, function(err, rows) {
                if (err || !rows || rows.length === 0) {
                    configuredAlertActions = {};
                    if (callback) callback(null, {});
                    return;
                }

                rows.forEach(function(row) {
                    try {
                        var config = row.config_json ? JSON.parse(row.config_json) : {};
                        var isEnabled = row.enabled === '1' || row.enabled === 'true';
                        // Consider "configured" if enabled AND has at least one non-empty config value
                        var isConfigured = isEnabled;
                        if (isEnabled && Object.keys(config).length > 0) {
                            for (var key in config) {
                                if (config.hasOwnProperty(key) && config[key]) {
                                    isConfigured = true;
                                    break;
                                }
                            }
                        }
                        configuredAlertActions[row.action_type] = {
                            enabled: isEnabled,
                            configured: isConfigured,
                            config: config
                        };
                    } catch (e) {
                        configuredAlertActions[row.action_type] = { enabled: false, configured: false, config: {} };
                    }
                });

                console.log('Loaded configured alert actions:', configuredAlertActions);
                if (callback) callback(null, configuredAlertActions);
            });
        },

        isActionConfigured: function(actionType) {
            // 'none' is always available
            if (actionType === 'none') return true;
            var config = configuredAlertActions[actionType];
            return config && config.enabled && config.configured;
        },

        // Get the "primary target" value from the global Settings config — used
        // as a placeholder/fallback in the per-row picker so users can see
        // "if I check this box and leave it blank, this is what gets used."
        getGlobalTarget: function(actionType) {
            var TARGET_KEY = { email: 'recipients', slack: 'webhook_url', teams: 'webhook_url', webhook: 'url' };
            var key = TARGET_KEY[actionType];
            if (!key) return '';
            var cfg = configuredAlertActions[actionType];
            if (!cfg || !cfg.enabled) return '';
            return (cfg.config && cfg.config[key]) || '';
        },

        isActionEnabled: function(actionType) {
            if (actionType === 'none') return true;
            var config = configuredAlertActions[actionType];
            return config && config.enabled;
        },

        getUnconfiguredWarning: function(actionType) {
            if (this.isActionConfigured(actionType)) return null;
            if (this.isActionEnabled(actionType)) {
                return 'This action is enabled but not fully configured. Configure it in Settings.';
            }
            return 'This action is not enabled. Enable and configure it in Settings first.';
        }
    };

    // ========================================
    // Source Type Discovery
    // ========================================
    var SourceTypeDiscovery = {
        getAvailableSourceTypes: function(callback) {
            // metadata is dramatically faster than tstats on large deployments —
            // it reads from index buckets metadata only, never touches events.
            // `index=* OR index=_*` covers both user and internal indexes
            // (bare `index=*` excludes `_*` — so the picker dropdown would
            // silently hide splunkd, _audit, _internal, etc., which are
            // legitimate sourcetypes a user may want to monitor).
            var query = '| metadata type=sourcetypes index=* OR index=_* | fields sourcetype | sort sourcetype';
            LookupManager.runSearch(query, callback);
        }
    };

    // ========================================
    // Discovery Source Icons
    // ========================================
    var discoveryIcons = {
        scheduled_searches: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>',
        correlation_searches: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path></svg>',
        dashboards: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>',
        audit_logs: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>',
        manual: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>'
    };

    var discoveryLabels = {
        scheduled_searches: 'Scheduled',
        correlation_searches: 'Correlation',
        dashboards: 'Dashboards',
        audit_logs: 'Audit Logs',
        manual: 'Manual'
    };

    // ========================================
    // Source Type Auto-Classifier
    // Maps known sourcetypes to importance levels
    // NOTE: Never auto-assigns VIP - only users can do that
    // ========================================
    var SourceTypeClassifier = {
        // Catalog data — populated from heartbeat_catalog.csv on init.
        // Until loaded, classify() returns null and callers fall back to defaults.
        _exact: {},          // { sourcetype: { importance, threshold, notes, category } }
        _patterns: [],       // [ { regex, importance, threshold, notes, category } ]
        _loaded: false,
        _loadCallbacks: [],

        // Load catalog from the bundled CSV lookup. Idempotent.
        loadCatalog: function(callback) {
            var self = this;
            if (self._loaded) {
                if (callback) callback(null, { exact: self._exact, patterns: self._patterns });
                return;
            }
            if (callback) self._loadCallbacks.push(callback);

            // Avoid duplicate concurrent loads
            if (self._loading) return;
            self._loading = true;

            var query = '| inputlookup heartbeat_catalog.csv';
            LookupManager.runSearch(query, function(err, rows) {
                self._loading = false;
                if (err) {
                    console.warn('[SA-Data-Heartbeat] catalog load failed:', err);
                    self._loaded = true; // mark loaded so we don't keep retrying; falls back to defaults
                } else {
                    (rows || []).forEach(function(row) {
                        var key = row.sourcetype;
                        if (!key) return;
                        var entry = {
                            importance: row.importance || 'medium',
                            threshold: parseInt(row.threshold, 10) || 60,
                            notes: row.notes || '',
                            category: row.category || 'other'
                        };
                        if (row.match_type === 'regex') {
                            try {
                                entry.regex = new RegExp(key, 'i');
                                self._patterns.push(entry);
                            } catch (e) {
                                console.warn('[SA-Data-Heartbeat] invalid regex in catalog:', key, e);
                            }
                        } else {
                            self._exact[key] = entry;
                        }
                    });
                    self._loaded = true;
                }
                var cbs = self._loadCallbacks;
                self._loadCallbacks = [];
                cbs.forEach(function(cb) {
                    cb(err || null, { exact: self._exact, patterns: self._patterns });
                });
            });
        },

        // Return all entries grouped by category (for the visual catalog UI)
        getByCategory: function() {
            var grouped = {};
            Object.keys(this._exact).forEach(function(st) {
                var e = this._exact[st];
                if (!grouped[e.category]) grouped[e.category] = [];
                grouped[e.category].push({ sourcetype: st, importance: e.importance, threshold: e.threshold, notes: e.notes });
            }, this);
            return grouped;
        },

        // Classify a sourcetype - returns { importance, threshold, notes } or null if unknown.
        // If catalog hasn't loaded yet, returns null (caller should use defaults).
        classify: function(sourcetype) {
            if (!sourcetype || !this._loaded) return null;

            if (this._exact[sourcetype]) {
                return this._exact[sourcetype];
            }

            // Case-insensitive exact lookup
            var lower = sourcetype.toLowerCase();
            for (var key in this._exact) {
                if (this._exact.hasOwnProperty(key) && key.toLowerCase() === lower) {
                    return this._exact[key];
                }
            }

            // Regex patterns
            for (var i = 0; i < this._patterns.length; i++) {
                var p = this._patterns[i];
                if (p.regex.test(sourcetype)) {
                    return {
                        importance: p.importance,
                        threshold: p.threshold,
                        notes: p.notes,
                        category: p.category
                    };
                }
            }
            return null;
        },

        // Get classification or defaults
        getClassification: function(sourcetype, defaultImportance, defaultThreshold) {
            var classification = this.classify(sourcetype);
            if (classification) {
                return {
                    importance: classification.importance,
                    threshold: classification.threshold,
                    notes: classification.notes,
                    autoClassified: true
                };
            }
            return {
                importance: defaultImportance || 'medium',
                threshold: defaultThreshold || 60,
                notes: '',
                autoClassified: false
            };
        }
    };

    // ========================================
    // UI Renderer
    // ========================================
    var UIRenderer = {
        renderMonitorTable: function(data) {
            var container = $('#sourcetype-monitor-table');
            if (!container.length) return;

            // Onboarding banner: show only when there's truly no data and the user
            // hasn't dismissed it. Hide as soon as any sourcetype exists.
            var $onboarding = $('#hb-onboarding');
            if ($onboarding.length) {
                var dismissed = false;
                try { dismissed = window.localStorage.getItem('sa_heartbeat:onboarding_dismissed') === '1'; } catch (e) {}
                var isEmpty = !data || data.length === 0;
                $onboarding.toggleClass('hb-hidden', !(isEmpty && !dismissed));
            }

            // Apply filters
            var filteredData = data.filter(function(row) {
                // Status filter: match exactly what the badge displays.
                if (currentFilters.status === 'flagged') {
                    if (row.status !== 'flagged') return false;
                } else if (currentFilters.status === 'good') {
                    // Healthy = good explicitly. Pending and flagged do NOT count.
                    if (row.status !== 'good') return false;
                } else if (currentFilters.status === 'pending') {
                    if (row.status !== 'pending') return false;
                }
                if (currentFilters.importance !== 'all' && row.importance !== currentFilters.importance) return false;
                return true;
            });

            // Sort:
            // 1. Importance order (VIP > critical > high > medium > low) — always
            // 2. Within same importance: flagged before non-flagged
            // 3. Tiebreak alphabetically by sourcetype
            var importanceOrder = { vip: 0, critical: 1, high: 2, medium: 3, low: 4 };
            filteredData.sort(function(a, b) {
                var impA = importanceOrder[a.importance] !== undefined ? importanceOrder[a.importance] : 4;
                var impB = importanceOrder[b.importance] !== undefined ? importanceOrder[b.importance] : 4;
                if (impA !== impB) return impA - impB;

                var aFlagged = a.status === 'flagged';
                var bFlagged = b.status === 'flagged';
                if (aFlagged !== bFlagged) return aFlagged ? -1 : 1;

                return (a.sourcetype || '').localeCompare(b.sourcetype || '');
            });

            // Pagination — slice filteredData for the current page
            var totalRows = filteredData.length;
            var totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;
            var startIdx = (currentPage - 1) * pageSize;
            var endIdx = Math.min(startIdx + pageSize, totalRows);
            var pagedData = filteredData.slice(startIdx, endIdx);

            var html = '<table class="sourcetype-table">' +
                '<thead><tr>' +
                '<th scope="col" class="th-row-num" style="width: 44px;" title="Row index — refer to rows by this number">#</th>' +
                '<th scope="col" style="width: 100px;">Status</th>' +
                '<th scope="col" class="th-primary-key" title="Sourcetype is the primary key — uniquely identifies each row in the monitored_sourcetypes KV-store collection">' +
                  '<svg aria-hidden="true" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#FD1875" stroke-width="2" style="vertical-align:-1px;margin-right:4px;">' +
                  '<circle cx="7" cy="14" r="4"></circle>' +
                  '<line x1="10" y1="11" x2="22" y2="3"></line>' +
                  '<line x1="22" y1="3" x2="22" y2="8"></line>' +
                  '<line x1="22" y1="3" x2="18" y2="7"></line>' +
                  '</svg>Sourcetype' +
                '</th>' +
                '<th scope="col" style="width: 90px;">Importance</th>' +
                '<th scope="col" style="width: 100px;">Threshold</th>' +
                '<th scope="col" style="width: 110px;">Last Seen</th>' +
                '<th scope="col" style="width: 80px;">Notes</th>' +
                '<th scope="col" style="width: 110px;">Alert Action</th>' +
                '<th scope="col" style="width: 80px;">Actions</th>' +
                '</tr></thead><tbody>';

            if (filteredData.length === 0) {
                html += '<tr><td colspan="9" style="text-align: center; padding: 40px;">' +
                    '<div class="empty-state">' +
                    '<div class="empty-state-icon">&#x1F4CA;</div>' +
                    '<div class="empty-state-title">No Sourcetypes Found</div>' +
                    '<div class="empty-state-description">' +
                    (data.length > 0 ? 'No sourcetypes match the current filters.' : 'Click "Run Discovery" to auto-detect important sourcetypes, or add them manually.') +
                    '</div>' +
                    '</div></td></tr>';
            } else {
                pagedData.forEach(function(row, localIdx) {
                    var rowNum = startIdx + localIdx + 1;
                    var status = row.status || 'pending';
                    var isFlagged = status === 'flagged';
                    var isPending = status === 'pending';
                    var importance = row.importance || 'medium';
                    var discoverySource = row.discovery_source || 'manual';
                    var usageCount = parseInt(row.usage_count, 10) || 0;
                    var minutesSince = parseFloat(row.minutes_since_seen) || 0;
                    var threshold = parseInt(row.threshold_minutes, 10) || 60;
                    var lastSeen = parseInt(row.last_seen, 10) || 0;
                    var alertAction = row.alert_action || 'none';
                    var alertActionConfig = row.alert_action_config || '';
                    var notes = row.notes || '';
                    var hasNotes = notes && notes.length > 0 && notes !== 'Auto-discovered';

                    // Row highlighting based on STATUS only (not importance)
                    // Red row = flagged status, NOT VIP importance
                    var rowClass = isFlagged ? 'flagged' : '';
                    if (isFlagged && importance === 'critical') {
                        rowClass += ' critical-flagged';
                    }

                    var timeClass = 'good';
                    if (minutesSince > threshold) {
                        timeClass = 'danger';
                    } else if (minutesSince > threshold * 0.75) {
                        timeClass = 'warning';
                    }

                    html += '<tr class="' + rowClass + '" data-row-num="' + rowNum + '">' +
                        // Row # column
                        '<td class="td-row-num">' + rowNum + '</td>' +
                        // Status column
                        '<td><span class="status-badge ' + (isFlagged ? 'flagged' : (isPending ? 'pending' : 'good')) + '"' +
                            (isPending ? ' title="Detection has not run on this sourcetype yet — click Run Detection to update"' : '') +
                            '>' +
                            (isFlagged ? 'FLAGGED' : (isPending ? 'PENDING' : 'GOOD')) + '</span></td>' +

                        // Source Type column with discovery info (not clickable)
                        '<td>' +
                            '<div class="sourcetype-name-wrapper">' +
                            '<div class="sourcetype-name">' +
                            '<strong>' + esc(row.sourcetype || 'Unknown') + '</strong>' +
                            '</div>' +
                            '<div class="sourcetype-meta">' +
                            '<span class="discovery-tag ' + discoverySource + '">' +
                                (discoveryIcons[discoverySource] || '') + ' ' +
                                (discoveryLabels[discoverySource] || discoverySource) +
                            '</span>' +
                            (usageCount > 0 ? '<span class="usage-count' + (usageCount >= 30 ? ' high' : '') + '">' + usageCount + ' uses</span>' : '') +
                            '</div>' +
                            '</div>' +
                        '</td>' +

                        // Importance column - clickable badge
                        '<td>' +
                            '<div class="importance-badge-wrapper">' +
                            '<span class="importance-badge ' + importance + '" data-sourcetype="' + esc(row.sourcetype || '') + '" data-current="' + importance + '">' +
                                (importance === 'vip' ? 'VIP' : importance.charAt(0).toUpperCase() + importance.slice(1)) +
                            '</span>' +
                            '</div>' +
                        '</td>' +

                        // Threshold column
                        '<td>' +
                            '<input type="number" class="threshold-input" ' +
                            'data-sourcetype="' + esc(row.sourcetype || '') + '" ' +
                            'value="' + threshold + '" min="1" max="9999">' +
                            '<span class="threshold-unit">min</span>' +
                        '</td>' +

                        // Last Seen column
                        '<td><span class="time-display ' + timeClass + '">' +
                            (lastSeen ? minutesSince.toFixed(1) + ' min' : 'Never') + '</span></td>' +

                        // Notes column - clickable badge
                        '<td>' +
                            '<div class="notes-badge-wrapper">' +
                            '<span class="notes-badge' + (hasNotes ? ' has-notes' : '') + '" data-sourcetype="' + esc(row.sourcetype || '') + '" data-notes="' + esc(notes) + '">' +
                                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>' +
                                (hasNotes ? '<span class="notes-count">!</span>' : '') +
                            '</span>' +
                            '</div>' +
                        '</td>' +

                        // Alert Action column - supports multiple actions as mini badges
                        '<td>' +
                            '<div class="alert-action-wrapper">' +
                            (function() {
                                var actions = (alertAction || 'none').split(',').map(function(a) { return a.trim(); });
                                var configs = (alertActionConfig || '').split('|');
                                if (actions.length === 1 && actions[0] === 'none') {
                                    return '<span class="alert-action-badge none" data-sourcetype="' + esc(row.sourcetype || '') + '" data-current="' + esc(alertAction) + '" data-config="' + esc(alertActionConfig) + '">None</span>';
                                }
                                // Whitelist action names so a malicious value can't inject a CSS class
                                // selector (e.g. `email"><img`) — only known action types are emitted.
                                var SAFE_ACTIONS = { email: 1, slack: 1, teams: 1, webhook: 1, pagerduty: 1, opsgenie: 1, servicenow: 1, jira: 1, splunk_soar: 1, syslog: 1, victorops: 1, script: 1 };
                                var badges = actions.map(function(action, idx) {
                                    var hasConfig = configs[idx] && configs[idx].length > 0;
                                    var safeCls = SAFE_ACTIONS[action] ? action : 'unknown';
                                    return '<span class="alert-action-mini ' + safeCls + (hasConfig ? ' configured' : '') + '" title="' + esc(hasConfig ? configs[idx] : action) + '">' +
                                        esc(action.charAt(0).toUpperCase() + action.slice(1)) +
                                        '</span>';
                                }).join('');
                                return '<span class="alert-actions-group" data-sourcetype="' + esc(row.sourcetype || '') + '" data-current="' + esc(alertAction) + '" data-config="' + esc(alertActionConfig) + '">' +
                                    badges +
                                    '</span>';
                            })() +
                            '</div>' +
                        '</td>' +

                        // Actions column
                        '<td>' +
                            '<button class="hb-btn hb-btn-icon btn-remove-sourcetype" ' +
                            'data-sourcetype="' + esc(row.sourcetype || '') + '" title="Remove">' +
                            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>' +
                            '</button>' +
                        '</td>' +
                        '</tr>';
                });
            }

            html += '</tbody></table>';

            // Pagination footer — page-size selector + "Showing N-M of T" + prev/next
            if (totalRows > 0) {
                html += '<div class="hb-pagination">' +
                    '<div class="hb-pg-pagesize">' +
                      '<label>Rows per page: ' +
                        '<select class="hb-pg-pagesize-select">' +
                          [10, 25, 50, 100].map(function(n) {
                            return '<option value="' + n + '"' + (n === pageSize ? ' selected' : '') + '>' + n + '</option>';
                          }).join('') +
                        '</select>' +
                      '</label>' +
                    '</div>' +
                    '<div class="hb-pg-info">' +
                      'Showing ' + (totalRows ? (startIdx + 1) : 0) + '–' + endIdx + ' of ' + totalRows +
                    '</div>' +
                    '<div class="hb-pg-controls">' +
                      '<button class="hb-btn hb-btn-secondary hb-btn-sm hb-pg-prev"' + (currentPage <= 1 ? ' disabled' : '') + ' aria-label="Previous page">&#x2190; Prev</button>' +
                      '<span class="hb-pg-pageinfo">Page ' + currentPage + ' of ' + totalPages + '</span>' +
                      '<button class="hb-btn hb-btn-secondary hb-btn-sm hb-pg-next"' + (currentPage >= totalPages ? ' disabled' : '') + ' aria-label="Next page">Next &#x2192;</button>' +
                    '</div>' +
                  '</div>';
            }

            container.html(html);
        },

        renderStats: function(data) {
            var total = data.length;
            var flagged = data.filter(function(r) { return r.status === 'flagged'; }).length;
            var good = data.filter(function(r) { return r.status === 'good'; }).length;
            var pending = data.filter(function(r) { return !r.status || r.status === 'pending'; }).length;
            var vipCount = data.filter(function(r) { return r.importance === 'vip'; }).length;
            var vipFlagged = data.filter(function(r) { return r.importance === 'vip' && r.status === 'flagged'; }).length;

            $('#stat-total').text(total);
            $('#stat-good').text(good);
            $('#stat-flagged').text(flagged);
            $('#stat-vip').text(vipCount);
            $('#stat-pending').text(pending);

            // Highlight VIP stat if any VIP sources are flagged
            if (vipFlagged > 0) {
                $('#stat-vip').closest('.stat-card').addClass('vip-alert');
            } else {
                $('#stat-vip').closest('.stat-card').removeClass('vip-alert');
            }
        },

        renderSourceTypeDropdown: function(availableTypes, monitoredTypes) {
            var monitoredSet = {};
            monitoredTypes.forEach(function(m) {
                monitoredSet[m.sourcetype] = true;
            });

            var html = '<option value="">Select a sourcetype...</option>';
            availableTypes.forEach(function(st) {
                if (!monitoredSet[st.sourcetype]) {
                    html += '<option value="' + esc(st.sourcetype) + '">' + esc(st.sourcetype) + '</option>';
                }
            });

            $('#add-sourcetype-select').html(html);
        }
    };

    // ========================================
    // Modal Manager
    // ========================================
    var ModalManager = {
        _trap: (window.HeartbeatUtils && window.HeartbeatUtils.FocusTrap) || null,

        show: function(modalId) {
            var $modal = $('#' + modalId);
            $modal.css('display', 'flex').addClass('active').attr('aria-hidden', 'false');
            // Make modal an accessible dialog if not already
            if (!$modal.attr('role')) $modal.attr('role', 'dialog').attr('aria-modal', 'true');
            // Trap focus + Escape closes
            if (this._trap) {
                var self = this;
                this._trap.activate($modal.find('.hb-modal').first(), {
                    onEscape: function () { self.hide(modalId); }
                });
            }
        },

        hide: function(modalId) {
            var $modal = $('#' + modalId);
            $modal.removeClass('active').attr('aria-hidden', 'true');
            if (this._trap) this._trap.deactivate();
            // Delay hiding to allow fade-out animation
            setTimeout(function() {
                if (!$modal.hasClass('active')) {
                    $modal.css('display', 'none');
                }
            }, 300);
        },

        init: function() {
            var self = this;
            // Backdrop click closes
            $(document).on('click', '.hb-modal-backdrop', function(e) {
                if ($(e.target).hasClass('hb-modal-backdrop')) {
                    self.hide($(this).attr('id'));
                }
            });
            // Close & cancel buttons
            $(document).on('click', '.hb-modal-close, .btn-modal-cancel', function() {
                var modalId = $(this).closest('.hb-modal-backdrop').attr('id');
                if (modalId) self.hide(modalId);
            });
        }
    };

    // ========================================
    // Event Handlers
    // ========================================
    function initEventHandlers() {
        // Add Source Type button
        $(document).on('click', '#btn-add-sourcetype', function() {
            SourceTypeDiscovery.getAvailableSourceTypes(function(err, available) {
                if (!err) {
                    LookupManager.getSourceTypes(function(err2, monitored) {
                        if (!err2) {
                            UIRenderer.renderSourceTypeDropdown(available, monitored);
                        }
                    });
                }
            });
            ModalManager.show('add-sourcetype-modal');
        });

        // Tab switching inside the Add modal
        $(document).on('click', '.hb-tab', function () {
            var which = $(this).data('tab');
            $('.hb-tab').removeClass('active').attr('aria-selected', 'false');
            $(this).addClass('active').attr('aria-selected', 'true');
            $('.hb-tab-panel').hide();
            $('.hb-tab-panel[data-panel="' + which + '"]').show();
        });

        // Live count for bulk textarea. Sourcetype names in Splunk are
        // alphanumeric plus `:`, `_`, `-`, `.` — anything else (HTML tags,
        // shell metacharacters, quotes) is invalid input and rejected.
        var VALID_SOURCETYPE = /^[A-Za-z0-9][A-Za-z0-9:_\-\.]{0,127}$/;
        function parseBulkSourcetypes() {
            var raw = $('#add-sourcetype-bulk').val() || '';
            return raw.split(/[\s,]+/)
                .map(function (s) { return s.trim(); })
                .filter(function (s) { return s.length > 0 && VALID_SOURCETYPE.test(s); });
        }
        function rejectedBulkSourcetypes() {
            var raw = $('#add-sourcetype-bulk').val() || '';
            return raw.split(/[\s,]+/)
                .map(function (s) { return s.trim(); })
                .filter(function (s) { return s.length > 0 && !VALID_SOURCETYPE.test(s); });
        }
        $(document).on('input', '#add-sourcetype-bulk', function () {
            $('#bulk-count').text(parseBulkSourcetypes().length);
        });

        // Confirm Add Source Type — supports single (dropdown) or bulk (textarea)
        $(document).on('click', '#btn-confirm-add', function () {
            var threshold = $('#add-threshold-input').val() || 60;
            var importance = $('#add-importance-select').val() || 'high';
            var notes = $('#add-notes-input').val() || '';
            var activeTab = $('.hb-tab.active').data('tab') || 'pick';

            var list;
            if (activeTab === 'paste') {
                list = parseBulkSourcetypes();
                var rejected = rejectedBulkSourcetypes();
                if (rejected.length > 0) {
                    Toast.error('Rejected ' + rejected.length + ' invalid name(s) (Splunk sourcetypes use A–Z, 0–9, `:_-.`): ' + rejected.slice(0, 3).join(', ') + (rejected.length > 3 ? '…' : ''));
                    return;
                }
                if (list.length === 0) {
                    Toast.warning('Enter at least one sourcetype');
                    return;
                }
            } else {
                var single = $('#add-sourcetype-select').val();
                if (!single) {
                    Toast.warning('Please select a sourcetype');
                    return;
                }
                list = [single];
            }

            // De-dupe against currently-monitored set, then add serially
            LookupManager.getSourceTypes(function (errExisting, existing) {
                var existingSet = {};
                var currentCount = 0;
                if (!errExisting && existing) {
                    currentCount = existing.length;
                    existing.forEach(function (e) { existingSet[e.sourcetype] = true; });
                }
                var toAdd = list.filter(function (s) { return !existingSet[s]; });
                var skipped = list.length - toAdd.length;

                if (toAdd.length === 0) {
                    Toast.warning('All ' + list.length + ' already monitored');
                    return;
                }

                // Cap enforcement: hard block at 1000, confirm at 500.
                var projected = currentCount + toAdd.length;
                if (projected > HARD_LIMIT_SOURCETYPES) {
                    Toast.error('Cannot add ' + toAdd.length + ' — would exceed the ' + HARD_LIMIT_SOURCETYPES +
                        ' sourcetype hard limit (current: ' + currentCount + '). Remove some first.');
                    return;
                }
                if (projected > SOFT_LIMIT_SOURCETYPES && currentCount <= SOFT_LIMIT_SOURCETYPES) {
                    var ok = window.confirm(
                        'You are about to monitor ' + projected + ' sourcetypes.\n\n' +
                        'Recommended ceiling is ' + SOFT_LIMIT_SOURCETYPES + '. Beyond this, the scheduled ' +
                        'detection search load and dashboard render time start to noticeably degrade.\n\n' +
                        'Continue?'
                    );
                    if (!ok) return;
                }

                var added = 0;
                var failed = 0;
                var $btn = $('#btn-confirm-add');
                var origText = $btn.text();
                $btn.prop('disabled', true).text('Adding ' + toAdd.length + '...');

                function addNext(i) {
                    if (i >= toAdd.length) {
                        $btn.prop('disabled', false).text(origText);
                        if (added > 0) {
                            var msg = 'Added ' + added + ' sourcetype' + (added !== 1 ? 's' : '');
                            if (skipped > 0) msg += ' (' + skipped + ' already monitored)';
                            if (failed > 0) msg += '; ' + failed + ' failed';
                            Toast.success(msg);
                            AuditLogger.log('added', toAdd.slice(0, added).join(','), '', importance, 'Bulk added ' + added + ' with ' + importance + ' importance, ' + threshold + ' min threshold');
                            ModalManager.hide('add-sourcetype-modal');
                            // reset form
                            $('#add-sourcetype-bulk').val('');
                            $('#bulk-count').text('0');
                            runDetection();
                        } else {
                            Toast.error('Failed to add sourcetypes');
                        }
                        return;
                    }
                    var st = toAdd[i];
                    LookupManager.addSourceType(st, threshold, importance, notes, function (err) {
                        if (err) failed++; else added++;
                        addNext(i + 1);
                    });
                }
                addNext(0);
            });
        });

        // Remove Source Type
        $(document).on('click', '.btn-remove-sourcetype', function() {
            var sourcetype = $(this).data('sourcetype');
            if (confirm('Remove "' + sourcetype + '" from monitoring?')) {
                LookupManager.removeSourceType(sourcetype, function(err) {
                    if (err) {
                        Toast.error('Failed to remove sourcetype');
                    } else {
                        Toast.success('Source type removed');
                        AuditLogger.log('removed', sourcetype, '', '', 'Removed from monitoring');
                        refreshData();
                    }
                });
            }
        });

        // Update Threshold on change - also recalculates status
        $(document).on('change', '.threshold-input', function() {
            var $input = $(this);
            var sourcetype = $input.data('sourcetype');
            var newThreshold = $input.val();
            var previousThreshold = $input.data('previous') || $input.prop('defaultValue');

            LookupManager.updateThreshold(sourcetype, newThreshold, function(err) {
                if (err) {
                    Toast.error('Failed to update threshold');
                } else {
                    Toast.success('Threshold updated - status recalculated');
                    AuditLogger.log('threshold_changed', sourcetype, previousThreshold, newThreshold, 'Threshold changed from ' + previousThreshold + ' to ' + newThreshold + ' minutes');
                    $input.data('previous', newThreshold);
                    refreshData();
                }
            });
        });

        // Click on importance badge to show popover
        $(document).on('click', '.importance-badge', function(e) {
            e.stopPropagation();
            var $badge = $(this);
            var sourcetype = $badge.data('sourcetype');
            var currentImportance = $badge.data('current');

            // Remove any existing popovers
            $('.importance-popover').remove();

            // Create popover
            var popoverHtml = '<div class="importance-popover">' +
                '<div class="importance-popover-option' + (currentImportance === 'vip' ? ' active' : '') + ' vip" data-value="vip">VIP</div>' +
                '<div class="importance-popover-option' + (currentImportance === 'critical' ? ' active' : '') + ' critical" data-value="critical">Critical</div>' +
                '<div class="importance-popover-option' + (currentImportance === 'high' ? ' active' : '') + ' high" data-value="high">High</div>' +
                '<div class="importance-popover-option' + (currentImportance === 'medium' ? ' active' : '') + ' medium" data-value="medium">Medium</div>' +
                '<div class="importance-popover-option' + (currentImportance === 'low' ? ' active' : '') + ' low" data-value="low">Low</div>' +
                '</div>';

            var $popover = $(popoverHtml);
            $popover.data('sourcetype', sourcetype);
            $popover.data('current', currentImportance);
            $popover.addClass('hb-portal');

            // Portal to body so we escape table/panel overflow:hidden — position fixed in viewport coords.
            $('body').append($popover);

            var POPOVER_HEIGHT = 220; // 5 options × ~40px + padding
            var POPOVER_WIDTH = 140;
            var badgeRect = $badge[0].getBoundingClientRect();
            var top = badgeRect.bottom + 4;
            var left = badgeRect.left;
            // Flip up if it would overflow the viewport bottom
            if (badgeRect.bottom + POPOVER_HEIGHT + 8 > window.innerHeight) {
                top = badgeRect.top - POPOVER_HEIGHT - 4;
            }
            // Clamp horizontally to keep it on-screen
            if (left + POPOVER_WIDTH + 8 > window.innerWidth) {
                left = window.innerWidth - POPOVER_WIDTH - 8;
            }
            if (left < 8) left = 8;
            $popover.css({ position: 'fixed', top: top + 'px', left: left + 'px' });

            // Animate in
            setTimeout(function() { $popover.addClass('active'); }, 10);
        });

        // Click on popover option
        $(document).on('click', '.importance-popover-option', function(e) {
            e.stopPropagation();
            var $option = $(this);
            var $popover = $option.closest('.importance-popover');
            var sourcetype = $popover.data('sourcetype');
            var currentImportance = $popover.data('current');
            var newImportance = $option.data('value');

            // Close popover
            $popover.removeClass('active');
            setTimeout(function() { $popover.remove(); }, 200);

            // No change needed
            if (newImportance === currentImportance) return;

            // VIP requires confirmation
            if (newImportance === 'vip') {
                ModalManager.show('vip-confirm-modal');
                $('#vip-confirm-sourcetype').text(sourcetype);
                window._pendingVipChange = {
                    sourcetype: sourcetype,
                    previousValue: currentImportance
                };
            } else {
                // Non-VIP changes proceed immediately
                LookupManager.updateImportance(sourcetype, newImportance, function(err) {
                    if (err) {
                        Toast.error('Failed to update importance');
                    } else {
                        Toast.success('Importance updated to ' + newImportance);
                        AuditLogger.log('importance_changed', sourcetype, currentImportance, newImportance, 'Importance changed from ' + currentImportance + ' to ' + newImportance);
                        refreshData();
                    }
                });
            }
        });

        // Close popover when clicking elsewhere
        $(document).on('click', function() {
            $('.importance-popover, .alert-action-popover, .notes-popover').removeClass('active');
            setTimeout(function() { $('.importance-popover, .alert-action-popover, .notes-popover').remove(); }, 200);
        });

        // Alert Action Types Configuration
        var alertActionTypes = {
            none: {
                label: 'None',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>',
                description: 'No alert action configured',
                configLabel: '',
                configPlaceholder: '',
                configHint: ''
            },
            email: {
                label: 'Email',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>',
                description: 'Send email notification',
                configLabel: 'Email Recipients',
                configPlaceholder: 'user@company.com, team@company.com',
                configHint: 'Comma-separated email addresses'
            },
            slack: {
                label: 'Slack',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 10c-.83 0-1.5-.67-1.5-1.5v-5c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5v5c0 .83-.67 1.5-1.5 1.5z"></path><path d="M20.5 10H19V8.5c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5-.67 1.5-1.5 1.5z"></path><path d="M9.5 14c.83 0 1.5.67 1.5 1.5v5c0 .83-.67 1.5-1.5 1.5S8 21.33 8 20.5v-5c0-.83.67-1.5 1.5-1.5z"></path><path d="M3.5 14H5v1.5c0 .83-.67 1.5-1.5 1.5S2 16.33 2 15.5 2.67 14 3.5 14z"></path><path d="M14 14.5c0-.83.67-1.5 1.5-1.5h5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5h-5c-.83 0-1.5-.67-1.5-1.5z"></path><path d="M15.5 19H14v1.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5-.67-1.5-1.5-1.5z"></path><path d="M10 9.5C10 8.67 9.33 8 8.5 8h-5C2.67 8 2 8.67 2 9.5S2.67 11 3.5 11h5c.83 0 1.5-.67 1.5-1.5z"></path><path d="M8.5 5H10V3.5C10 2.67 9.33 2 8.5 2S7 2.67 7 3.5 7.67 5 8.5 5z"></path></svg>',
                description: 'Post to Slack via incoming webhook',
                configLabel: 'Slack Webhook URL',
                configPlaceholder: 'https://hooks.slack.com/services/T0/B0/...',
                configHint: 'Incoming webhook URL — channel names like #security do not work'
            },
            teams: {
                label: 'MS Teams',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>',
                description: 'Post to Microsoft Teams',
                configLabel: 'Teams Webhook URL',
                configPlaceholder: 'https://outlook.office.com/webhook/...',
                configHint: 'Incoming webhook URL for your Teams channel'
            },
            pagerduty: {
                label: 'PagerDuty',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 17H2a3 3 0 0 0 3-3V9a7 7 0 0 1 14 0v5a3 3 0 0 0 3 3zm-8.27 4a2 2 0 0 1-3.46 0"></path></svg>',
                description: 'Trigger PagerDuty incident',
                configLabel: 'Integration Key',
                configPlaceholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                configHint: 'PagerDuty Events API v2 integration key'
            },
            opsgenie: {
                label: 'OpsGenie',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 8v4"></path><path d="M12 16h.01"></path></svg>',
                description: 'Create OpsGenie alert',
                configLabel: 'API Key',
                configPlaceholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
                configHint: 'OpsGenie API integration key'
            },
            victorops: {
                label: 'Splunk On-Call',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15.05 5A5 5 0 0 1 19 8.95M15.05 1A9 9 0 0 1 23 8.94m-1 7.98v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg>',
                description: 'Create Splunk On-Call incident',
                configLabel: 'Routing Key',
                configPlaceholder: 'your-routing-key',
                configHint: 'VictorOps/Splunk On-Call routing key'
            },
            servicenow: {
                label: 'ServiceNow',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>',
                description: 'Create ServiceNow incident',
                configLabel: 'Instance & Table',
                configPlaceholder: 'instance.service-now.com|incident',
                configHint: 'Format: instance.service-now.com|table_name'
            },
            jira: {
                label: 'Jira',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg>',
                description: 'Create Jira ticket',
                configLabel: 'Project & Issue Type',
                configPlaceholder: 'PROJECT-KEY|Bug',
                configHint: 'Format: PROJECT-KEY|IssueType (e.g., SEC|Incident)'
            },
            splunk_soar: {
                label: 'Splunk SOAR',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>',
                description: 'Trigger Splunk SOAR playbook',
                configLabel: 'Container Label',
                configPlaceholder: 'data_heartbeat_alert',
                configHint: 'SOAR container label for automation'
            },
            webhook: {
                label: 'Webhook',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>',
                description: 'Call custom webhook URL',
                configLabel: 'Webhook URL',
                configPlaceholder: 'https://api.example.com/alerts',
                configHint: 'POST request with JSON payload'
            },
            syslog: {
                label: 'Syslog',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>',
                description: 'Send syslog message',
                configLabel: 'Syslog Server',
                configPlaceholder: 'syslog.company.com:514',
                configHint: 'Format: hostname:port (UDP)'
            },
            script: {
                label: 'Script',
                icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>',
                description: 'Run custom script',
                configLabel: 'Script Path',
                configPlaceholder: '/opt/splunk/etc/apps/SA-Data-Heartbeat/bin/alert.sh',
                configHint: 'Path to executable script on Splunk server'
            }
        };

        // Click on alert action badge to show modal (supports multiple actions)
        $(document).on('click', '.alert-action-badge, .alert-actions-group, .add-action-btn', function(e) {
            e.stopPropagation();
            var $badge = $(this);
            var sourcetype = $badge.data('sourcetype');
            // Support comma-separated list of actions
            var currentActions = ($badge.data('current') || 'none').split(',').map(function(a) { return a.trim(); });
            var currentConfigs = ($badge.data('config') || '').split('|').map(function(c) { return c.trim(); });

            // If only action is 'none', treat as empty
            if (currentActions.length === 1 && currentActions[0] === 'none') {
                currentActions = [];
            }

            // Store current state for the modal
            window._pendingActionChange = {
                sourcetype: sourcetype,
                previousActions: currentActions.slice(),
                previousConfigs: currentConfigs.slice()
            };

            // Build action options HTML with checkboxes for multi-select.
            // Only show action types the dispatcher actually implements — the
            // rest (pagerduty / opsgenie / servicenow / jira / splunk_soar /
            // syslog / victorops) are scaffolded but ship in v1.3. Showing
            // them today would silently drop alerts when the user picks them.
            var SHIPPED_ACTIONS = { email: 1, slack: 1, teams: 1, webhook: 1 };
            var actionsHtml = '';
            for (var actionKey in alertActionTypes) {
                if (actionKey === 'none') continue; // Skip 'none' - user just unchecks all
                if (!SHIPPED_ACTIONS[actionKey]) continue; // hide v1.3-pending types
                var action = alertActionTypes[actionKey];
                var isChecked = currentActions.indexOf(actionKey) !== -1;
                var configIndex = currentActions.indexOf(actionKey);
                var actionConfig = configIndex !== -1 && currentConfigs[configIndex] ? currentConfigs[configIndex] : '';

                // Check if action is configured in Settings
                var isConfigured = AlertActionsConfigManager.isActionConfigured(actionKey);
                var isEnabled = AlertActionsConfigManager.isActionEnabled(actionKey);
                var unconfiguredClass = !isConfigured ? ' unconfigured' : '';
                var statusBadge = '';
                if (!isEnabled) {
                    statusBadge = '<span class="action-config-badge disabled">Not Enabled</span>';
                } else if (!isConfigured) {
                    statusBadge = '<span class="action-config-badge partial">Needs Config</span>';
                } else {
                    statusBadge = '<span class="action-config-badge ready">Ready</span>';
                }

                actionsHtml += '<div class="action-type-option' + (isChecked ? ' selected' : '') + unconfiguredClass + '" data-action="' + actionKey + '" data-configured="' + isConfigured + '">' +
                    '<div class="action-checkbox">' +
                    '<input type="checkbox" class="action-check" ' + (isChecked ? 'checked' : '') + ' />' +
                    '</div>' +
                    '<div class="action-type-icon">' + action.icon + '</div>' +
                    '<div class="action-type-info">' +
                    '<div class="action-type-label">' + action.label + statusBadge + '</div>' +
                    '<div class="action-type-desc">' + action.description + '</div>' +
                    '</div>' +
                    '<input type="text" class="action-config-inline" placeholder="' + esc((function(){var gt=AlertActionsConfigManager.getGlobalTarget(actionKey); return gt ? 'Default: ' + gt : (action.configPlaceholder || 'Config...');})()) + '" value="' + esc(actionConfig) + '" title="Leave blank to use the global default configured in Settings" />' +
                    '</div>';
            }

            // Update modal content
            $('#action-modal-sourcetype').text(sourcetype);
            $('#action-types-list').html(actionsHtml);

            // Hide the old single config section (configs are now inline)
            $('#action-config-section').hide();

            // Show modal
            ModalManager.show('action-config-modal');
        });

        // Click on action type option in modal - toggle checkbox
        $(document).on('click', '.action-type-option', function(e) {
            e.stopPropagation();
            var $option = $(this);
            var $checkbox = $option.find('.action-check');
            var actionKey = $option.data('action');

            // Don't toggle if clicking directly on input field
            if ($(e.target).hasClass('action-config-inline')) {
                return;
            }

            // Check if trying to enable an unconfigured action
            var isCurrentlyChecked = $checkbox.prop('checked');
            if (!isCurrentlyChecked && !AlertActionsConfigManager.isActionConfigured(actionKey)) {
                // Show warning for unconfigured action
                var warningMsg = AlertActionsConfigManager.getUnconfiguredWarning(actionKey);
                if (warningMsg) {
                    Toast.warning(warningMsg);
                    // Still allow selection but highlight that it needs config
                }
            }

            // Toggle checkbox
            var isChecked = $checkbox.prop('checked');
            $checkbox.prop('checked', !isChecked);
            $option.toggleClass('selected', !isChecked);

            // Focus config input if now checked
            if (!isChecked) {
                $option.find('.action-config-inline').focus();
            }
        });

        // Handle direct checkbox clicks
        $(document).on('click', '.action-check', function(e) {
            e.stopPropagation();
            var $option = $(this).closest('.action-type-option');
            var isChecked = $(this).prop('checked');
            $option.toggleClass('selected', isChecked);

            if (isChecked) {
                $option.find('.action-config-inline').focus();
            }
        });

        // Save action from modal - supports multiple actions
        $(document).on('click', '#btn-save-action', function(e) {
            e.stopPropagation();
            var pending = window._pendingActionChange;
            if (!pending) return;

            // Collect all checked actions and their configs
            var selectedActions = [];
            var selectedConfigs = [];

            $('.action-type-option').each(function() {
                var $option = $(this);
                var $checkbox = $option.find('.action-check');
                if ($checkbox.prop('checked')) {
                    var actionKey = $option.data('action');
                    var configValue = $option.find('.action-config-inline').val() || '';
                    selectedActions.push(actionKey);
                    selectedConfigs.push(configValue);
                }
            });

            // If no actions selected, set to 'none'
            var newAction = selectedActions.length > 0 ? selectedActions.join(',') : 'none';
            var newConfig = selectedConfigs.length > 0 ? selectedConfigs.join('|') : '';

            var sourcetype = pending.sourcetype;
            var previousActions = pending.previousActions.join(',') || 'none';
            var previousConfigs = pending.previousConfigs.join('|') || '';

            // Close modal
            ModalManager.hide('action-config-modal');
            window._pendingActionChange = null;

            // Save changes
            LookupManager.updateAlertAction(sourcetype, newAction, newConfig, function(err) {
                if (err) {
                    Toast.error('Failed to update alert action');
                } else {
                    // Build user-friendly message
                    var actionLabels = selectedActions.map(function(a) {
                        return alertActionTypes[a] ? alertActionTypes[a].label : a;
                    });
                    var msg = actionLabels.length > 0
                        ? 'Alert actions set: ' + actionLabels.join(', ')
                        : 'Alert actions cleared';
                    Toast.success(msg);
                    AuditLogger.log('alert_action_changed', sourcetype, previousActions, newAction, 'Alert actions changed to: ' + newAction);
                    refreshData();
                }
            });
        });

        // Cancel action modal
        $(document).on('click', '#btn-cancel-action', function() {
            ModalManager.hide('action-config-modal');
            window._pendingActionChange = null;
        });

        // Click on notes badge to show notes popover
        $(document).on('click', '.notes-badge', function(e) {
            e.stopPropagation();
            var $badge = $(this);
            var sourcetype = $badge.data('sourcetype');
            var currentNotes = $badge.data('notes') || '';

            // Remove any existing popovers
            $('.notes-popover, .alert-action-popover, .importance-popover').remove();

            // Create notes popover
            var emptyHint = currentNotes ? '' :
                '<div class="notes-empty-hint">No notes yet. Add ticket numbers, timelines, or runbook links here.</div>';
            var popoverHtml = '<div class="notes-popover">' +
                '<div class="notes-popover-header">' +
                    '<span class="notes-popover-title">Notes for ' + sourcetype + '</span>' +
                '</div>' +
                '<div class="notes-popover-body">' +
                    emptyHint +
                    '<textarea class="notes-textarea" placeholder="e.g. Ticket INC0012345 — onboarded 2026-04-15 — owner: SecOps">' + currentNotes + '</textarea>' +
                '</div>' +
                '<div class="notes-popover-footer">' +
                    '<button class="hb-btn hb-btn-secondary hb-btn-sm btn-cancel-notes">Cancel</button>' +
                    '<button class="hb-btn hb-btn-primary hb-btn-sm btn-save-notes">Save Notes</button>' +
                '</div>' +
                '</div>';

            var $popover = $(popoverHtml);
            $popover.data('sourcetype', sourcetype);
            $popover.data('original-notes', currentNotes);
            $popover.addClass('hb-portal');

            // Portal to body so it escapes table/panel overflow:hidden
            $('body').append($popover);

            var NOTES_POPOVER_HEIGHT = 380;
            var NOTES_POPOVER_WIDTH = 360;
            var br = $badge[0].getBoundingClientRect();
            var top = br.bottom + 4;
            var left = br.left;
            if (br.bottom + NOTES_POPOVER_HEIGHT + 8 > window.innerHeight) {
                top = br.top - NOTES_POPOVER_HEIGHT - 4;
                if (top < 8) top = 8;
            }
            if (left + NOTES_POPOVER_WIDTH + 8 > window.innerWidth) {
                left = window.innerWidth - NOTES_POPOVER_WIDTH - 8;
            }
            if (left < 8) left = 8;
            $popover.css({ position: 'fixed', top: top + 'px', left: left + 'px' });

            // Animate in and focus textarea
            setTimeout(function() {
                $popover.addClass('active');
                $popover.find('.notes-textarea').focus();
            }, 10);
        });

        // Cancel notes editing
        $(document).on('click', '.btn-cancel-notes', function(e) {
            e.stopPropagation();
            var $popover = $(this).closest('.notes-popover');
            $popover.removeClass('active');
            setTimeout(function() { $popover.remove(); }, 200);
        });

        // Save notes
        $(document).on('click', '.btn-save-notes', function(e) {
            e.stopPropagation();
            var $btn = $(this);
            var $popover = $btn.closest('.notes-popover');
            var sourcetype = $popover.data('sourcetype');
            var originalNotes = $popover.data('original-notes') || '';
            var newNotes = $popover.find('.notes-textarea').val() || '';

            // Close popover
            $popover.removeClass('active');
            setTimeout(function() { $popover.remove(); }, 200);

            // Skip if no changes
            if (newNotes === originalNotes) {
                return;
            }

            // Save changes
            LookupManager.updateNotes(sourcetype, newNotes, function(err) {
                if (err) {
                    Toast.error('Failed to update notes');
                } else {
                    Toast.success('Notes updated successfully');
                    AuditLogger.log('notes_updated', sourcetype, originalNotes, newNotes, 'Notes updated');
                    refreshData();
                }
            });
        });

        // Prevent clicks inside popovers from closing them
        $(document).on('click', '.notes-popover, .alert-action-popover', function(e) {
            e.stopPropagation();
        });

        // VIP Confirmation - Proceed
        $(document).on('click', '#btn-confirm-vip', function() {
            var pending = window._pendingVipChange;
            if (pending) {
                LookupManager.updateImportance(pending.sourcetype, 'vip', function(err) {
                    if (err) {
                        Toast.error('Failed to update importance');
                    } else {
                        Toast.success(pending.sourcetype + ' marked as VIP - Ultra Critical');
                        AuditLogger.log('importance_changed', pending.sourcetype, pending.previousValue, 'vip', 'Marked as VIP - Ultra Critical');
                        refreshData();
                    }
                });
                window._pendingVipChange = null;
            }
            ModalManager.hide('vip-confirm-modal');
        });

        // VIP Confirmation - Cancel
        $(document).on('click', '#btn-cancel-vip', function() {
            window._pendingVipChange = null;
            ModalManager.hide('vip-confirm-modal');
        });

        // Onboarding banner dismiss
        $(document).on('click', '#hb-onboarding-dismiss', function() {
            try { window.localStorage.setItem('sa_heartbeat:onboarding_dismissed', '1'); } catch (e) {}
            $('#hb-onboarding').addClass('hb-hidden');
        });

        // Shared helper: write a list of picks into monitored_sourcetypes via outputlookup,
        // then refresh the dashboard. Picks are objects { sourcetype, importance, threshold, notes, source }.
        function applyPicks(picks, sourceLabel, $btn, auditAction) {
            if (!picks || picks.length === 0) {
                Toast.warning('No sourcetypes to add. Try a different option.');
                if ($btn) $btn.prop('disabled', false);
                return;
            }
            // Cap enforcement before write (async lookup count first)
            LookupManager.getSourceTypes(function (cntErr, existing) {
                var current = (cntErr || !existing) ? 0 : existing.length;
                var projected = current + picks.length;
                if (projected > HARD_LIMIT_SOURCETYPES) {
                    Toast.error('Cannot add ' + picks.length + ' — would exceed the ' + HARD_LIMIT_SOURCETYPES +
                        ' sourcetype hard limit (current: ' + current + ').');
                    if ($btn) $btn.prop('disabled', false);
                    return;
                }
                if (projected > SOFT_LIMIT_SOURCETYPES && current <= SOFT_LIMIT_SOURCETYPES) {
                    var ok = window.confirm(
                        'You are about to monitor ' + projected + ' sourcetypes.\n\n' +
                        'Recommended ceiling is ' + SOFT_LIMIT_SOURCETYPES + '. Continue?'
                    );
                    if (!ok) {
                        if ($btn) $btn.prop('disabled', false);
                        return;
                    }
                }
                applyPicksUnchecked(picks, sourceLabel, $btn, auditAction);
            });
        }

        // Internal: the original applyPicks body, post cap-check.
        function applyPicksUnchecked(picks, sourceLabel, $btn, auditAction) {
            var ts = Math.floor(Date.now() / 1000);
            var subsearches = picks.map(function(p) {
                return '[| makeresults' +
                    ' | eval sourcetype="' + escapeStr(p.sourcetype) + '"' +
                    ', threshold_minutes=' + (parseInt(p.threshold, 10) || 60) +
                    ', last_seen=0' +
                    ', minutes_since_seen=0' +
                    ', status="pending"' +
                    ', importance="' + escapeStr(p.importance || 'medium') + '"' +
                    ', discovery_source="' + escapeStr(p.source || sourceLabel) + '"' +
                    ', usage_count=' + (parseInt(p.usage_count, 10) || 0) +
                    ', added_by="' + escapeStr(currentUser) + '"' +
                    ', added_time=' + ts +
                    ', notes="' + escapeStr(p.notes || '') + '"' +
                    ' | fields - _time]';
            }).join(' | append ');
            var query = '| inputlookup ' + LOOKUP_FILE + ' | append ' + subsearches +
                ' | dedup sourcetype | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;
            LookupManager.runSearch(query, function(err) {
                if ($btn) $btn.prop('disabled', false);
                if (err) {
                    Toast.error('Failed to write lookup: ' + (err.message || ''));
                    return;
                }
                Toast.success('Added ' + picks.length + ' sourcetypes (' + sourceLabel + ')');
                AuditLogger.log(auditAction, '_all_', '', String(picks.length),
                    'Quick start added ' + picks.length + ' sourcetypes via ' + sourceLabel);
                // Auto-run detection so newly-added rows transition out of pending immediately
                runDetection();
            });
        }

        // Quick Start — Curated: hand-picked balanced 10 across Windows / EDR /
        // identity / cloud / firewall / Linux. Best when user wants a fast SOC
        // baseline regardless of what their environment currently ingests.
        var CURATED_PICKS = [
            'WinEventLog:Security',
            'WinEventLog:Microsoft-Windows-Sysmon/Operational',
            'crowdstrike:events',
            'okta:log',
            'azure:aad:signin',
            'aws:cloudtrail',
            'aws:guardduty',
            'pan:traffic',
            'cisco:asa',
            'linux_secure'
        ];
        $(document).on('click', '#btn-quickstart-curated', function() {
            var $btn = $(this).prop('disabled', true);
            Toast.info('Loading catalog...');
            SourceTypeClassifier.loadCatalog(function(err) {
                if (err) {
                    Toast.error('Catalog failed to load');
                    $btn.prop('disabled', false);
                    return;
                }
                var picks = CURATED_PICKS.map(function(st) {
                    var e = SourceTypeClassifier._exact[st] || {};
                    return {
                        sourcetype: st,
                        importance: e.importance || 'critical',
                        threshold: e.threshold || 30,
                        notes: e.notes || 'Curated quick-start pick',
                        source: 'curated'
                    };
                });
                applyPicks(picks, 'curated', $btn, 'quickstart_curated');
            });
        });

        // Quick Start — Recommend from data: run tstats to find what the user
        // actually ingests, intersect with the catalog, take the top 10 by count
        // preferring critical/high importance. Best when they want zero
        // false-flag noise from unused vendors.
        $(document).on('click', '#btn-quickstart-recommend', function() {
            var $btn = $(this).prop('disabled', true);
            Toast.info('Scanning your environment with tstats...');
            SourceTypeClassifier.loadCatalog(function(err) {
                if (err) {
                    Toast.error('Catalog failed to load');
                    $btn.prop('disabled', false);
                    return;
                }
                // tstats over tsidx — fast, no event scan. Limited to last 24h
                // (the SearchManager default earliest_time); covers typical
                // operational footprint without hammering the indexer.
                var query = '| tstats summariesonly=false count where index=* by sourcetype ' +
                    '| sort - count';
                LookupManager.runSearch(query, function(err, rows) {
                    if (err || !rows) {
                        Toast.error('tstats scan failed: ' + (err ? (err.message || '') : 'no rows returned'));
                        $btn.prop('disabled', false);
                        return;
                    }
                    if (rows.length === 0) {
                        Toast.warning('No sourcetypes found in any index. Make sure data is being ingested.');
                        $btn.prop('disabled', false);
                        return;
                    }

                    // Score each environmental sourcetype: catalog importance > usage count
                    var importanceWeight = { critical: 1000, high: 500, medium: 100, low: 10 };
                    var scored = rows.map(function(r) {
                        var st = r.sourcetype;
                        var classification = SourceTypeClassifier.classify(st);
                        var importance = (classification && classification.importance) || 'medium';
                        var threshold = (classification && classification.threshold) || 60;
                        var notes = (classification && classification.notes) || '';
                        var category = (classification && classification.category) || 'other';
                        var usageCount = parseInt(r.count, 10) || 0;
                        var score = (importanceWeight[importance] || 0) + Math.log10(usageCount + 1);
                        return {
                            sourcetype: st,
                            importance: importance,
                            threshold: threshold,
                            notes: notes,
                            category: category,
                            usage_count: usageCount,
                            score: score,
                            source: classification ? 'data_recommended' : 'data_recommended_uncatalogued'
                        };
                    });
                    scored.sort(function(a, b) { return b.score - a.score; });
                    var picks = scored.slice(0, 10);
                    Toast.info('Found ' + rows.length + ' sourcetypes. Adding the top ' + picks.length + '.');
                    applyPicks(picks, 'data-recommended', $btn, 'quickstart_recommend');
                });
            });
        });

        // Onboarding "Run Discovery instead" button — same as the toolbar Run Discovery
        $(document).on('click', '#btn-onboarding-discover', function() {
            $('#btn-run-discovery').click();
        });

        // Filter chips
        $(document).on('click', '.filter-chip', function() {
            var filterType = $(this).data('filter-type');
            var filterValue = $(this).data('filter-value');

            $(this).siblings('.filter-chip').removeClass('active');
            $(this).addClass('active');

            currentFilters[filterType] = filterValue;
            FilterStorage.save(currentFilters);
            currentPage = 1; // reset to page 1 on filter change
            refreshData();
        });

        // Pagination — page-size selector
        $(document).on('change', '.hb-pg-pagesize-select', function() {
            var newSize = parseInt($(this).val(), 10);
            if ([10, 25, 50, 100].indexOf(newSize) === -1) return;
            pageSize = newSize;
            currentPage = 1;
            try { window.localStorage.setItem('sa_heartbeat:page_size', String(pageSize)); } catch (e) {}
            refreshData();
        });

        // Pagination — prev / next
        $(document).on('click', '.hb-pg-prev', function() {
            if ($(this).is(':disabled')) return;
            currentPage = Math.max(1, currentPage - 1);
            refreshData();
        });
        $(document).on('click', '.hb-pg-next', function() {
            if ($(this).is(':disabled')) return;
            currentPage = currentPage + 1;
            refreshData();
        });

        // Auto-poll the lookup every 30s. Skip when:
        //   - tab is hidden (no point burning cycles for an offscreen page)
        //   - a popover, modal, or notes editor is open (would yank the user's UI)
        //   - the user is actively typing in an input (preserve in-flight edits)
        function shouldSkipAutoPoll() {
            if (document.hidden) return true;
            if ($('.hb-modal-backdrop.active').length) return true;
            if ($('.importance-popover, .notes-popover, .alert-action-popover').length) return true;
            var ae = document.activeElement;
            if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT')) return true;
            return false;
        }
        setInterval(function () {
            if (!shouldSkipAutoPoll()) refreshData();
        }, AUTO_POLL_MS);
        // Resume immediately when tab regains focus
        document.addEventListener('visibilitychange', function () {
            if (!document.hidden) refreshData();
        });

        // Run Detection Now button — shows loading state during 3-15s search
        $(document).on('click', '#btn-run-detection', function() {
            var $btn = $(this);
            if ($btn.hasClass('hb-loading')) return;
            var orig = $btn.html();
            $btn.addClass('hb-loading').data('orig-html', orig).html('Running');
            // runDetection ends with a refreshData() in its callback chain; we wrap it
            // with a finalizer that restores the button. If the caller passes a callback,
            // chain through it.
            runDetection(function () {
                $btn.removeClass('hb-loading').html($btn.data('orig-html') || orig);
            });
        });

        // Run Discovery button — also shows loading state
        $(document).on('click', '#btn-run-discovery', function() {
            var $btn = $(this);
            if ($btn.hasClass('hb-loading')) return;
            // First-time disclosure: Auto Discovery reads saved-search and
            // dashboard *definitions* (not event data) across the deployment
            // to extract sourcetype references. Confirm before the first run
            // so Splunk Cloud co-tenants understand what's being read.
            var key = 'sa_heartbeat:discovery_disclosure_acked';
            var acked = false;
            try { acked = window.localStorage.getItem(key) === '1'; } catch (e) {}
            if (!acked) {
                var ok = window.confirm(
                    'Auto Discovery will read saved-search and dashboard definitions across ' +
                    'this Splunk deployment to extract sourcetype references — it scans search ' +
                    'STRINGS, not event data. Results are filtered by your role\'s read permissions.\n\n' +
                    'No data leaves Splunk. Proceed?'
                );
                if (!ok) return;
                try { window.localStorage.setItem(key, '1'); } catch (e) {}
            }
            var orig = $btn.html();
            $btn.addClass('hb-loading').data('orig-html', orig).html('Scanning');
            runDiscovery(function () {
                $btn.removeClass('hb-loading').html($btn.data('orig-html') || orig);
            });
        });

        // One-click "Enable Monitoring" CTA on the status banner — bypasses the
        // splunkweb proxy enable-bug by hitting our custom REST endpoint.
        $(document).on('click', '#btn-enable-monitoring', function () {
            var $btn = $(this);
            if ($btn.hasClass('hb-loading')) return;
            var orig = $btn.html();
            $btn.addClass('hb-loading').data('orig-html', orig).html('Enabling');
            splunkAjax({
                url: '/en-US/splunkd/__raw/servicesNS/nobody/SA-Data-Heartbeat/data_heartbeat/admin',
                type: 'POST',
                data: { action: 'enable_all' },
                complete: function (xhr) {
                    $btn.removeClass('hb-loading').html($btn.data('orig-html') || orig);
                    if (xhr.status >= 400) {
                        Toast.error('Couldn\'t enable monitoring (' + xhr.status + '). Open Settings to toggle manually.');
                        return;
                    }
                    Toast.success('Monitoring enabled. Detection will run on the next 5-min cycle.');
                    updateScheduleBanner();
                }
            });
        });
    }

    // Wrapper for ajax calls that adds the Splunk Web CSRF header on writes.
    // The dispatcher and admin endpoint both need this on POST.
    function splunkAjax(opts) {
        var method = (opts.type || opts.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') {
            var csrf = '';
            var m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
            if (m) csrf = decodeURIComponent(m[1]);
            opts.headers = $.extend({}, opts.headers || {}, {
                'X-Splunk-Form-Key': csrf,
                'X-Requested-With': 'XMLHttpRequest'
            });
        }
        return $.ajax(opts);
    }

    // ========================================
    // Data Refresh
    // ========================================
    function refreshData() {
        LookupManager.getSourceTypes(function(err, data) {
            if (err) {
                Toast.error('Failed to load sourcetypes: ' + (err.message || 'unknown error'));
                // Render an inline error so the table area isn't just blank
                $('#sourcetype-monitor-table').html(
                    '<div class="empty-state error-state" role="alert">' +
                    '<div class="empty-state-icon" aria-hidden="true">&#x26A0;</div>' +
                    '<div class="empty-state-title">Couldn\'t load sourcetypes</div>' +
                    '<div class="empty-state-description">' +
                    'Check that the <code>monitored_sourcetypes</code> KV-store collection is healthy and that you have read permission on it. ' +
                    'See the README troubleshooting section for help.' +
                    '</div>' +
                    '</div>'
                );
                return;
            }
            UIRenderer.renderMonitorTable(data);
            UIRenderer.renderStats(data);
        });
    }

    // ========================================
    // Run Detection Search
    // ========================================
    // Concurrent runDetection calls race on outputlookup and can clobber each
    // other's status writes. Module-level flag serializes them. UI callers
    // either get queued behind the in-flight run (button click) or skip
    // (auto-refresh) — either way, only one runs at a time.
    var _detectionInFlight = false;
    function runDetection(onDone) {
        if (typeof onDone !== 'function') onDone = function () {};
        if (_detectionInFlight) {
            // Skip duplicate — the in-flight run will refresh the dashboard
            // when it completes, so subsequent callers don't need to wait.
            onDone();
            return;
        }
        _detectionInFlight = true;
        Toast.info('Running detection search...');

        // Detection reads the KV-store lookup (the live source of truth — the
        // CSV fallback is only used for the initial seed). `metadata` reads
        // index bucket metadata only — no event scans, safe on multi-TB
        // tenants and doesn't require accelerated data models (unlike
        // `tstats summariesonly=t`, which silently returns empty on
        // non-accelerated environments and would mark every sourcetype as
        // flagged with last_seen=0). `index=* OR index=_*` covers both user
        // and internal indexes (the bare `index=*` excludes `_*`).
        var query = '| inputlookup ' + LOOKUP_FILE +
            ' | rename sourcetype as monitored_sourcetype ' +
            '| join type=left monitored_sourcetype ' +
            '[| metadata type=sourcetypes index=* OR index=_* ' +
            '| rename lastTime as last_event_time, sourcetype as monitored_sourcetype ' +
            '| stats max(last_event_time) as last_event_time by monitored_sourcetype] ' +
            '| eval now_time = now() ' +
            '| eval last_seen = coalesce(last_event_time, 0) ' +
            '| eval minutes_since_seen = round((now_time - last_seen) / 60, 1) ' +
            '| eval status = if(minutes_since_seen > tonumber(threshold_minutes) OR last_seen = 0, "flagged", "good") ' +
            '| table monitored_sourcetype, threshold_minutes, last_seen, minutes_since_seen, status, importance, discovery_source, usage_count, added_by, added_time, notes, alert_action, alert_action_config ' +
            '| rename monitored_sourcetype as sourcetype ' +
            '| eval _key = sourcetype ' +
            '| outputlookup ' + LOOKUP_FILE;

        LookupManager.runSearch(query, function(err) {
            _detectionInFlight = false;
            if (err) {
                Toast.error('Detection search failed');
            } else {
                Toast.success('Detection complete');
                LookupManager.getSourceTypes(function(err2, data) {
                    if (!err2 && data) {
                        var flagged = data.filter(function(r) { return r.status === 'flagged'; }).length;
                        var good = data.length - flagged;
                        AuditLogger.log('detection_run', '_all_', '', '', 'Detection completed - ' + flagged + ' flagged, ' + good + ' good');
                    }
                });
                refreshData();
            }
            onDone();
        });
    }

    // ========================================
    // Run Auto-Discovery
    // ========================================
    function runDiscovery(onDone) {
        Toast.info('Running auto-discovery... This may take a moment.');
        if (typeof onDone !== 'function') onDone = function () {};

        // Discovery via | metadata — reads bucket metadata only, no event scan.
        // Performant on large multi-TB deployments where `index=*` event scans
        // would time out. `index=* OR index=_*` includes internal indexes so
        // discovery surfaces splunkd / _audit / etc. alongside user indexes
        // (consistent with Detection and the picker dropdown).
        var query = '| metadata type=sourcetypes index=* OR index=_* ' +
            '| sort - totalCount ' +
            '| head 50 ' +
            '| rename totalCount as usage_count ' +
            '| eval threshold_minutes=60, status="pending", importance="medium", discovery_source="metadata", added_by="discovery", added_time=now(), notes="Auto-discovered" ' +
            '| table sourcetype, threshold_minutes, status, importance, discovery_source, usage_count, added_by, added_time, notes';

        LookupManager.runSearch(query, function(err, results) {
            if (err) {
                Toast.error('Discovery failed');
                return;
            }

            if (results && results.length > 0) {
                // Merge with existing data
                LookupManager.getSourceTypes(function(err2, existing) {
                    if (err2) {
                        Toast.error('Failed to merge discovery results');
                        return;
                    }

                    var existingSet = {};
                    existing.forEach(function(e) {
                        existingSet[e.sourcetype] = true;
                    });

                    var newSourceTypes = results.filter(function(r) {
                        return !existingSet[r.sourcetype];
                    });

                    if (newSourceTypes.length === 0) {
                        Toast.warning('No new sourcetypes discovered');
                        return;
                    }

                    // Count how many were auto-classified
                    var autoClassifiedCount = 0;

                    // Add them to the lookup with auto-classification
                    var mergeQuery = '| inputlookup ' + LOOKUP_FILE;
                    newSourceTypes.forEach(function(st) {
                        // Auto-classify based on known sourcetype patterns
                        // Never auto-assigns VIP - only users can do that
                        var classification = SourceTypeClassifier.getClassification(st.sourcetype, 'medium', 60);
                        if (classification.autoClassified) {
                            autoClassifiedCount++;
                        }

                        var notesText = classification.autoClassified
                            ? classification.notes
                            : 'Auto-discovered';

                        mergeQuery += ' | append [| makeresults | eval sourcetype="' + LookupManager.escapeString(st.sourcetype) + '"' +
                            ', threshold_minutes=' + classification.threshold +
                            ', last_seen=0' +
                            ', minutes_since_seen=0' +
                            ', status="pending"' +
                            ', importance="' + classification.importance + '"' +
                            ', discovery_source="audit_logs"' +
                            ', usage_count=' + (parseInt(st.usage_count, 10) || 0) +
                            ', added_by="discovery"' +
                            ', added_time=' + Math.floor(Date.now() / 1000) +
                            ', notes="' + LookupManager.escapeString(notesText) + '"' +
                            ' | fields - _time]';
                    });
                    mergeQuery += ' | dedup sourcetype | eval _key=sourcetype | outputlookup ' + LOOKUP_FILE;

                    // Show summary message
                    if (autoClassifiedCount > 0) {
                        Toast.success('Discovered ' + newSourceTypes.length + ' new sourcetypes (' + autoClassifiedCount + ' auto-classified)');
                    } else {
                        Toast.success('Discovered ' + newSourceTypes.length + ' new sourcetypes');
                    }

                    LookupManager.runSearch(mergeQuery, function(err3) {
                        if (err3) {
                            Toast.error('Failed to save discovered sourcetypes');
                        } else {
                            AuditLogger.log('discovery_run', '_all_', '', '', 'Auto-discovery found ' + newSourceTypes.length + ' new sourcetypes (' + autoClassifiedCount + ' auto-classified)');
                            refreshData();
                        }
                    });
                });
            } else {
                Toast.warning('No sourcetypes discovered');
                AuditLogger.log('discovery_run', '_all_', '', '', 'Auto-discovery ran but found no new sourcetypes');
            }
            onDone();
        });
    }

    // ========================================
    // Initialize
    // ========================================
    function init() {
        console.log('SA-Data-Heartbeat: Initializing...');
        ModalManager.init();
        initEventHandlers();

        // Load the sourcetype classification catalog from CSV.
        // Until this resolves, classify() returns null and add/discovery flows fall back to defaults.
        SourceTypeClassifier.loadCatalog();

        // One-time CSV → KV migration. If the KV-store collection is empty,
        // dispatch the migration saved search to seed it from the bundled CSV.
        // Idempotent: re-running upserts by _key so already-migrated rows
        // get refreshed, not duplicated. Re-fires refreshData when done so
        // the table shows the freshly-seeded rows on first load.
        migrateCsvToKvIfNeeded(function () { refreshData(); });

        // Permission-aware UI: hide write controls for non-admin/sc_admin users.
        if (window.HeartbeatUtils && window.HeartbeatUtils.Permissions) {
            window.HeartbeatUtils.Permissions.load().then(function (perms) {
                if (!perms.canWrite) {
                    $('#btn-add-sourcetype, #btn-run-discovery, #btn-run-detection').addClass('hb-hidden');
                    $('.heartbeat-app').addClass('hb-readonly');
                }
            });
        }

        // Keyboard shortcuts (skipped when user is typing in an input/textarea/select)
        if (window.HeartbeatUtils && window.HeartbeatUtils.Shortcuts) {
            var SC = window.HeartbeatUtils.Shortcuts;
            SC.register({ key: 'd', description: 'Run Discovery',
                handler: function () { $('#btn-run-discovery').click(); } });
            SC.register({ key: 'a', description: 'Add Sourcetype',
                handler: function () { $('#btn-add-sourcetype').click(); } });
            SC.register({ key: '?', description: 'Show keyboard shortcuts',
                handler: function () {
                    var lines = SC.help().map(function (s) { return s.key + ' — ' + s.description; }).join('\n');
                    Toast.info('Shortcuts:\n' + lines, 8000);
                } });
        }

        // Wire the How This Works button
        $(document).on('click', '#btn-how-this-works', function () {
            ModalManager.show('how-this-works-modal');
        });

        // Show/hide the "scheduled searches not enabled" banner based on real state.
        updateScheduleBanner();

        // Load configured alert actions from Settings, then refresh data
        AlertActionsConfigManager.loadConfiguredActions(function() {
            refreshData();
        });

        // Re-check the scheduled-search banner every minute (user may have flipped
        // toggles in Settings since the page loaded).
        setInterval(updateScheduleBanner, 60000);

        // Refresh configured actions every 5 minutes in case Settings changed
        setInterval(function() {
            AlertActionsConfigManager.loadConfiguredActions();
        }, 300000);
    }

    // One-time CSV → KV migration on dashboard load. After seeding, fires the
    // onDone callback so the caller can refreshData() and pick up the new rows.
    function migrateCsvToKvIfNeeded(onDone) {
        if (typeof onDone !== 'function') onDone = function () {};
        var checkQuery = '| inputlookup monitored_sourcetypes_lookup | stats count';
        LookupManager.runSearch(checkQuery, function (err, rows) {
            if (err) return onDone();
            var count = parseInt((rows && rows[0] && rows[0].count) || '0', 10);
            if (count > 0) return onDone();
            console.log('[hb] KV empty, seeding from CSV...');
            var seed = '| inputlookup monitored_sourcetypes_csv | eval _key=sourcetype | eval alert_action=coalesce(alert_action,"none") | eval alert_action_config=coalesce(alert_action_config,"") | outputlookup monitored_sourcetypes_lookup append=true';
            LookupManager.runSearch(seed, function (e2) {
                if (!e2) console.log('[hb] KV seed complete');
                onDone();
            });
        });
    }

    // Read the 3 scheduled saved-search states and show a status banner
    // if ANY are disabled. Keeps the banner accurate when the user toggles
    // searches in the Settings page without refreshing Monitor.
    function updateScheduleBanner() {
        var $banner = $('#hb-status-banner');
        if (!$banner.length) return;
        var names = [
            { name: 'Data Heartbeat - Source Type Monitor', label: 'Detection' },
            { name: 'Data Heartbeat Alert - Flagged Sources', label: 'Alerts' },
            { name: 'Data Heartbeat - Auto Discovery',       label: 'Auto Discovery' }
        ];
        var results = new Array(names.length);
        var done = 0;
        names.forEach(function (entry, idx) {
            $.ajax({
                url: '/en-US/splunkd/__raw/servicesNS/nobody/SA-Data-Heartbeat/saved/searches/' +
                     encodeURIComponent(entry.name) + '?output_mode=json',
                cache: false
            }).then(function (data) {
                var c = (data.entry && data.entry[0] && data.entry[0].content) || {};
                results[idx] = { label: entry.label, disabled: !!c.disabled };
            }, function () {
                results[idx] = { label: entry.label, disabled: true };
            }).always(function () {
                done++;
                if (done !== names.length) return;
                var off = results.filter(function (r) { return r.disabled; }).map(function (r) { return r.label; });
                if (off.length === 0) {
                    $banner.addClass('hb-hidden');
                    return;
                }
                var msg = off.length === 3
                    ? 'None of the scheduled searches are running. Enable them in Settings so detection, alerts, and auto-discovery work.'
                    : off.join(', ') + (off.length === 1 ? ' is' : ' are') + ' disabled. Enable in Settings so this dashboard updates on its own.';
                $('#hb-status-banner-text').text(' — ' + msg);
                $banner.removeClass('hb-hidden');
            });
        });
    }

    $(document).ready(init);

    // Expose for debugging
    window.HeartbeatApp = {
        LookupManager: LookupManager,
        AuditLogger: AuditLogger,
        SourceTypeClassifier: SourceTypeClassifier,
        AlertActionsConfigManager: AlertActionsConfigManager,
        Toast: Toast,
        refreshData: refreshData,
        runDetection: runDetection,
        runDiscovery: runDiscovery
    };
});
