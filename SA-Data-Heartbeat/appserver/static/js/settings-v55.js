/**
 * SA-Data-Heartbeat - Settings Page JavaScript
 * Handles settings management and saved search configuration
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
    var SETTINGS_FILE = 'heartbeat_settings.csv';
    var ALERT_ACTIONS_FILE = 'heartbeat_alert_actions.csv';
    var DETECTION_SEARCH_NAME = 'Data Heartbeat - Source Type Monitor';

    // Store alert action configs
    var alertActionConfigs = {};

    // Toast and escapeString come from HeartbeatUtils (loaded by js/utils.js).
    // Fallback shims if utils.js failed to load — keeps the page functional.
    var HU = window.HeartbeatUtils || {};
    var Toast = HU.Toast || {
        success: function(m) { console.log('[toast/success]', m); },
        error:   function(m) { console.error('[toast/error]', m); },
        warning: function(m) { console.warn('[toast/warning]', m); },
        info:    function(m) { console.info('[toast/info]', m); }
    };
    function escapeStr(s) {
        if (HU.escapeString) return HU.escapeString(s);
        if (s === null || s === undefined) return '';
        return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    // HTML-attribute / text escape — for innerHTML splices where the value
    // could contain markup. The settings lookup is admin-writable so a
    // malicious or buggy value (e.g. setting_value="<script>alert(1)</script>")
    // would otherwise execute when rendered into the current-settings table.
    function escapeHtml(s) {
        if (HU.escapeHtml) return HU.escapeHtml(s);
        if (s === null || s === undefined) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // ========================================
    // Settings Manager
    // ========================================
    var SettingsManager = {
        runSearch: function(query, callback) {
            var searchId = 'hb_settings_search_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
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
                // Short-circuit empty result sets (results 'data' event won't fire on count=0)
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
                results.on('error', function(err) { done(err); });
            });

            sm.on('search:error', function(err) { done(err); });
            sm.on('search:fail', function(err) { done(err || new Error('search failed')); });

            // Watchdog: 60s timeout
            window.setTimeout(function() {
                if (!settled) done(new Error('Search timed out after 60s'));
            }, 60000);
        },

        getSettings: function(callback) {
            var query = '| inputlookup ' + SETTINGS_FILE;
            this.runSearch(query, callback);
        },

        updateSetting: function(settingName, settingValue, callback) {
            var query = '| inputlookup ' + SETTINGS_FILE +
                ' | eval setting_value=if(setting_name="' + this.escapeString(settingName) + '", "' + this.escapeString(settingValue) + '", setting_value)' +
                ' | outputlookup ' + SETTINGS_FILE;

            this.runSearch(query, callback);
        },

        escapeString: escapeStr
    };

    // ========================================
    // Saved Search Manager
    // ========================================
    // The three saved searches that comprise "monitoring" — toggling Enable
    // Scheduled Detection enables/disables ALL of them as a unit.
    var ALL_SEARCH_NAMES = [
        'Data Heartbeat - Source Type Monitor',
        'Data Heartbeat Alert - Flagged Sources',
        'Data Heartbeat - Auto Discovery'
    ];

    console.log('SA-Data-Heartbeat Settings: loaded');

    // Splunk Web requires the X-Splunk-Form-Key CSRF header on POST requests.
    // Read it from the splunkweb_csrf_token_<port> cookie (port varies by deployment).
    function getCsrfToken() {
        var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        if (match) return decodeURIComponent(match[1]);
        // Fallback: some Splunk versions expose it on window
        return (window.$C && window.$C.CSRF_TOKEN) || '';
    }

    // Wrap $.ajax to always include the CSRF header on POST/DELETE/PUT.
    function splunkAjax(opts) {
        var method = (opts.type || opts.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') {
            opts.headers = $.extend({}, opts.headers || {}, {
                'X-Splunk-Form-Key': getCsrfToken(),
                'X-Requested-With': 'XMLHttpRequest'
            });
        }
        return $.ajax(opts);
    }

    var SavedSearchManager = {
        getSearchUrl: function (name) {
            return '/en-US/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/saved/searches/' + encodeURIComponent(name);
        },

        // Read status of the primary detection search (used by displayCurrentSettings)
        getSearchStatus: function (callback) {
            splunkAjax({
                url: this.getSearchUrl(DETECTION_SEARCH_NAME),
                type: 'GET',
                data: { output_mode: 'json' },
                success: function (response) {
                    var entry = response.entry && response.entry[0];
                    if (entry) {
                        var d = entry.content.disabled;
                        var isDisabled = (d === true || d === 1 || d === '1');
                        callback(null, {
                            disabled: isDisabled,
                            cron_schedule: entry.content.cron_schedule
                        });
                    } else {
                        callback(new Error('Search not found'));
                    }
                },
                error: function (xhr, status, error) {
                    callback(new Error('Failed to read detection search: ' + (error || status)));
                }
            });
        },

        // Toggle one named saved search. Splunk's REST proxy has a quirk where
        // the FIRST write to a stanza without a local override sometimes creates
        // an empty header before writing fields — we verify state and retry.
        enableSearchByName: function (name, enabled, callback) {
            var self = this;
            var url = this.getSearchUrl(name);
            var expected = !enabled;

            function attempt(remainingRetries) {
                splunkAjax({
                    url: url,
                    type: 'POST',
                    data: {
                        disabled: enabled ? '0' : '1',
                        is_scheduled: enabled ? '1' : '0',
                        output_mode: 'json'
                    },
                    complete: function (xhr) {
                        if (xhr.status >= 400) {
                            return callback(new Error('REST ' + xhr.status + ' updating ' + name));
                        }
                        splunkAjax({
                            url: url + '?output_mode=json',
                            type: 'GET',
                            success: function (resp) {
                                var entry = resp.entry && resp.entry[0];
                                var actualDisabled = entry && entry.content && entry.content.disabled;
                                if (actualDisabled === expected) {
                                    return callback(null);
                                }
                                if (remainingRetries > 0) {
                                    return attempt(remainingRetries - 1);
                                }
                                callback(new Error('Splunk did not persist the change for "' + name + '". Open Reports → ' + name + ' to enable manually.'));
                            },
                            // Verify-state GET failed. Previously this swallowed
                            // the error and reported success — meaning a partial-
                            // state toggle would silently look like it worked.
                            // Now we report the error so the UI can surface a
                            // toast and the user can retry / open Splunk Manager.
                            error: function (xhr, status, error) {
                                callback(new Error(
                                    'Could not verify "' + name + '" state after toggle: ' +
                                    (error || status || 'unknown')
                                ));
                            }
                        });
                    }
                });
            }
            attempt(2);
        },

        // Backwards-compat alias for the primary detection search.
        enableSearch: function (enabled, callback) {
            return this.enableSearchByName(DETECTION_SEARCH_NAME, enabled, callback);
        },

        // Update the cron on the primary detection search
        updateSchedule: function (cronSchedule, callback) {
            splunkAjax({
                url: this.getSearchUrl(DETECTION_SEARCH_NAME),
                type: 'POST',
                data: { cron_schedule: cronSchedule, output_mode: 'json' },
                complete: function (xhr) {
                    if (xhr.status >= 400) {
                        callback(new Error('Schedule update failed: REST ' + xhr.status));
                    } else {
                        callback(null);
                    }
                }
            });
        }
    };

    // ========================================
    // UI Functions
    // ========================================
    function loadSettings() {
        SettingsManager.getSettings(function(err, settings) {
            if (err) {
                Toast.error('Failed to load settings');
                return;
            }

            var settingsMap = {};
            settings.forEach(function(s) {
                settingsMap[s.setting_name] = s.setting_value;
            });

            // Update UI
            $('#setting-detection-frequency').val(settingsMap.detection_frequency || '5');
            $('#setting-default-threshold').val(settingsMap.default_threshold || '60');

            // Display current settings
            displayCurrentSettings(settingsMap);
        });

        // Read state for all 3 toggles in parallel.
        var toggleConfigs = [
            { name: 'Data Heartbeat - Source Type Monitor', toggleId: 'setting-enable-detection', labelId: 'detection-status-label', isPrimary: true },
            { name: 'Data Heartbeat Alert - Flagged Sources', toggleId: 'setting-enable-alert', labelId: 'alert-status-label' },
            { name: 'Data Heartbeat - Auto Discovery', toggleId: 'setting-enable-discovery', labelId: 'discovery-status-label' }
        ];
        toggleConfigs.forEach(function (cfg) {
            splunkAjax({
                url: SavedSearchManager.getSearchUrl(cfg.name) + '?output_mode=json',
                type: 'GET',
                success: function (resp) {
                    var entry = resp.entry && resp.entry[0];
                    if (!entry) return;
                    var content = entry.content || {};
                    var isEnabled = !content.disabled;
                    $('#' + cfg.toggleId).prop('checked', isEnabled);
                    $('#' + cfg.labelId).text(isEnabled ? 'Enabled' : 'Disabled');
                    if (cfg.isPrimary) {
                        var cron = content.cron_schedule || '*/5 * * * *';
                        var match = cron.match(/\*\/(\d+)/);
                        if (match) $('#setting-detection-frequency').val(match[1]);
                    }
                }
            });
        });
    }

    function displayCurrentSettings(settings) {
        var html = '<table class="sourcetype-table" style="margin: 0;">' +
            '<thead><tr>' +
            '<th>Setting</th>' +
            '<th>Value</th>' +
            '<th>Description</th>' +
            '</tr></thead><tbody>';

        // Detection settings
        for (var key in settings) {
            if (settings.hasOwnProperty(key)) {
                var desc = '';
                switch(key) {
                    case 'detection_frequency':
                        desc = 'Detection search frequency in minutes';
                        break;
                    case 'default_threshold':
                        desc = 'Default threshold for new sourcetypes';
                        break;
                }

                html += '<tr>' +
                    '<td><strong>' + escapeHtml(key) + '</strong></td>' +
                    '<td>' + escapeHtml(settings[key]) + '</td>' +
                    '<td style="color: var(--hb-text-muted);">' + escapeHtml(desc) + '</td>' +
                '</tr>';
            }
        }

        // Alert action names for display
        var actionNames = {
            email: 'Email',
            slack: 'Slack',
            pagerduty: 'PagerDuty',
            teams: 'Microsoft Teams',
            webhook: 'Webhook',
            servicenow: 'ServiceNow'
        };

        // Enabled alert actions
        var enabledActions = [];
        var configuredActions = [];
        for (var actionType in alertActionConfigs) {
            if (alertActionConfigs.hasOwnProperty(actionType)) {
                var config = alertActionConfigs[actionType];
                if (config.enabled) {
                    var actionName = actionNames[actionType] || actionType;
                    enabledActions.push(actionName);
                    if (AlertActionsManager.isConfigured(actionType)) {
                        configuredActions.push(actionName);
                    }
                }
            }
        }

        // Add alert actions row. Values come from `actionNames` (controlled
        // dict) but action_type keys can be anything stored in the lookup —
        // escape defensively so a hostile `action_type` value can't smuggle
        // markup into the settings summary.
        if (enabledActions.length > 0) {
            html += '<tr>' +
                '<td><strong>enabled_alert_actions</strong></td>' +
                '<td>' + escapeHtml(enabledActions.join(', ')) + '</td>' +
                '<td style="color: var(--hb-text-muted);">Alert actions enabled for use</td>' +
                '</tr>';
        }

        if (configuredActions.length > 0) {
            html += '<tr>' +
                '<td><strong>configured_alert_actions</strong></td>' +
                '<td><span style="color: var(--hb-success);">' + escapeHtml(configuredActions.join(', ')) + '</span></td>' +
                '<td style="color: var(--hb-text-muted);">Alert actions with complete configuration</td>' +
                '</tr>';
        }

        html += '</tbody></table>';

        if (Object.keys(settings).length === 0 && enabledActions.length === 0) {
            html = '<p style="color: var(--hb-text-muted); text-align: center; padding: 20px;">No settings configured</p>';
        }

        $('#current-settings-display').html(html);
    }

    function saveSettings() {
        var frequency = $('#setting-detection-frequency').val();
        var threshold = $('#setting-default-threshold').val();
        var enabled = $('#setting-enable-detection').is(':checked');

        // Collect alert action configs from UI
        collectAlertActionConfigs();

        // Save to lookup
        SettingsManager.updateSetting('detection_frequency', frequency, function(err) {
            if (err) {
                Toast.error('Failed to save detection frequency');
                return;
            }

            SettingsManager.updateSetting('default_threshold', threshold, function(err2) {
                if (err2) {
                    Toast.error('Failed to save default threshold');
                    return;
                }

                // Save alert action configs
                AlertActionsManager.saveConfigs(function(err2b) {
                    if (err2b) {
                        console.warn('Failed to save alert action configs:', err2b);
                    }

                    // Update saved search schedule
                    var cronSchedule = '*/' + frequency + ' * * * *';
                    SavedSearchManager.updateSchedule(cronSchedule, function(err3) {
                        if (err3) {
                            Toast.error('Failed to update search schedule');
                            return;
                        }

                        // Update enabled state
                        SavedSearchManager.enableSearch(enabled, function(err4) {
                            if (err4) {
                                Toast.error('Failed to update search state');
                                return;
                            }

                            Toast.success('Settings saved successfully');
                            // Prevent change detection during reload
                            isLoading = true;
                            loadSettings(); // Refresh display
                            loadAlertActions(); // Refresh alert actions
                            // Re-capture original values and reset action bar after save
                            // Use longer timeout to ensure ALL loadSettings async calls complete
                            setTimeout(function() {
                                captureOriginalValues();
                                hasUnsavedChanges = false;
                                updateActionBar();
                                // Keep isLoading true briefly to catch any late callbacks
                                setTimeout(function() {
                                    isLoading = false;
                                }, 500);
                            }, 2000);
                        });
                    });
                });
            });
        });
    }

    // ========================================
    // Change Detection for Action Bar
    // ========================================
    var originalValues = {};
    var hasUnsavedChanges = false;
    var isLoading = false; // Prevent change detection during load/save

    function captureOriginalValues() {
        originalValues = {
            frequency: $('#setting-detection-frequency').val(),
            threshold: $('#setting-default-threshold').val(),
            enabled: $('#setting-enable-detection').is(':checked')
        };
    }

    function checkForChanges() {
        // Skip if we're loading/refreshing settings
        if (isLoading) return;

        var currentFrequency = $('#setting-detection-frequency').val();
        var currentThreshold = $('#setting-default-threshold').val();
        var currentEnabled = $('#setting-enable-detection').is(':checked');

        hasUnsavedChanges = (
            currentFrequency !== originalValues.frequency ||
            currentThreshold !== originalValues.threshold ||
            currentEnabled !== originalValues.enabled
        );

        updateActionBar();
    }

    // Legacy "Save / Discard" action-bar UI was replaced by per-control
    // auto-save in v1.2.0; the corresponding DOM elements (#btn-save-settings,
    // #btn-discard-settings, #settings-status-text) were removed from
    // settings.xml but the callers stayed. Keep this function as a no-op
    // shim so the call sites in saveSettings()/checkForChanges() don't have
    // to be touched in this patch — the dirty-state and beforeunload warning
    // for the alert-action text fields still work independently.
    function updateActionBar() { /* intentional no-op — see comment */ }

    function discardChanges() {
        $('#setting-detection-frequency').val(originalValues.frequency);
        $('#setting-default-threshold').val(originalValues.threshold);
        $('#setting-enable-detection').prop('checked', originalValues.enabled);
        $('#detection-status-label').text(originalValues.enabled ? 'Enabled' : 'Disabled');
        hasUnsavedChanges = false;
        updateActionBar();
        Toast.warning('Changes discarded');
    }

    // ========================================
    // Alert Actions Manager
    // ========================================
    var AlertActionsManager = {
        loadConfigs: function(callback) {
            var query = '| inputlookup ' + ALERT_ACTIONS_FILE + ' | table action_type, enabled, config_json';
            SettingsManager.runSearch(query, function(err, rows) {
                if (err || !rows || rows.length === 0) {
                    // Initialize with empty configs
                    alertActionConfigs = {};
                    if (callback) callback(null, {});
                    return;
                }

                rows.forEach(function(row) {
                    try {
                        alertActionConfigs[row.action_type] = {
                            enabled: row.enabled === '1' || row.enabled === 'true',
                            config: row.config_json ? JSON.parse(row.config_json) : {}
                        };
                    } catch (e) {
                        alertActionConfigs[row.action_type] = { enabled: false, config: {} };
                    }
                });

                if (callback) callback(null, alertActionConfigs);
            });
        },

        saveConfigs: function(callback) {
            // Build the lookup data
            var rows = [];
            for (var actionType in alertActionConfigs) {
                if (alertActionConfigs.hasOwnProperty(actionType)) {
                    var config = alertActionConfigs[actionType];
                    rows.push({
                        action_type: actionType,
                        enabled: config.enabled ? '1' : '0',
                        config_json: JSON.stringify(config.config || {})
                    });
                }
            }

            if (rows.length === 0) {
                if (callback) callback(null);
                return;
            }

            // Create SPL to write lookup
            var makeResultsParts = rows.map(function(row) {
                return '| makeresults | eval action_type="' + row.action_type + '", enabled="' + row.enabled + '", config_json="' + SettingsManager.escapeString(row.config_json) + '" | fields - _time';
            });

            var query = makeResultsParts.join(' | append [') + Array(makeResultsParts.length).join(']') + ' | outputlookup ' + ALERT_ACTIONS_FILE;

            SettingsManager.runSearch(query, callback);
        },

        isConfigured: function(actionType) {
            var config = alertActionConfigs[actionType];
            if (!config || !config.enabled) return false;

            // Check if config has any non-empty values
            var configObj = config.config || {};
            for (var key in configObj) {
                if (configObj.hasOwnProperty(key) && configObj[key]) {
                    return true;
                }
            }
            return false;
        },

        getConfiguredActions: function() {
            var configured = [];
            for (var actionType in alertActionConfigs) {
                if (this.isConfigured(actionType)) {
                    configured.push(actionType);
                }
            }
            return configured;
        }
    };

    // ========================================
    // Alert Actions UI Functions
    // ========================================
    function loadAlertActions() {
        AlertActionsManager.loadConfigs(function(err, configs) {
            updateAlertActionsUI();
            // Refresh current settings display to show alert actions
            refreshCurrentSettingsDisplay();
        });
    }

    function refreshCurrentSettingsDisplay() {
        // Re-fetch settings and display with alert actions
        SettingsManager.getSettings(function(err, settings) {
            if (err) return;
            var settingsMap = {};
            settings.forEach(function(s) {
                settingsMap[s.setting_name] = s.setting_value;
            });
            displayCurrentSettings(settingsMap);
        });
    }

    function updateAlertActionsUI() {
        var configuredCount = 0;

        $('.action-accordion-item').each(function() {
            var $item = $(this);
            var actionType = $item.data('action');
            var config = alertActionConfigs[actionType] || { enabled: false, config: {} };

            // Update toggle
            $item.find('.action-enabled-toggle').prop('checked', config.enabled);

            // Update input fields
            var configObj = config.config || {};
            $item.find('.action-config-input').each(function() {
                var $input = $(this);
                var field = $input.data('field');
                if (configObj[field]) {
                    $input.val(configObj[field]);
                }
            });

            // Update status badge
            var isConfigured = AlertActionsManager.isConfigured(actionType);
            var $badge = $item.find('.action-status-badge');
            if (isConfigured) {
                $badge.text('Configured').addClass('configured');
                $item.addClass('configured');
                configuredCount++;
            } else if (config.enabled) {
                $badge.text('Enabled').addClass('configured');
            } else {
                $badge.text('Not Configured').removeClass('configured');
                $item.removeClass('configured');
            }
        });

        // Update header badge
        var $countBadge = $('#configured-actions-count');
        $countBadge.text(configuredCount + ' configured');
        if (configuredCount > 0) {
            $countBadge.addClass('configured');
        } else {
            $countBadge.removeClass('configured');
        }
    }

    function collectAlertActionConfigs() {
        $('.action-accordion-item').each(function() {
            var $item = $(this);
            var actionType = $item.data('action');

            var enabled = $item.find('.action-enabled-toggle').is(':checked');
            var config = {};

            $item.find('.action-config-input').each(function() {
                var $input = $(this);
                var field = $input.data('field');
                var value = $input.val();
                if (value) {
                    config[field] = value;
                }
            });

            alertActionConfigs[actionType] = {
                enabled: enabled,
                config: config
            };
        });
    }

    // ========================================
    // Event Handlers
    // ========================================
    // Inline "Saved ✓" indicator next to a control
    function showSavedIndicator($control, ok) {
        var $row = $control.closest('.settings-row, .action-accordion-item');
        if (!$row.length) $row = $control.parent();
        $row.find('.hb-saved-indicator').remove();
        var ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        var html = ok
            ? '<span class="hb-saved-indicator hb-saved-ok">✓ Saved ' + ts + '</span>'
            : '<span class="hb-saved-indicator hb-saved-err">✗ Save failed</span>';
        $row.append(html);
        // Fade out after 3s on success
        if (ok) {
            window.setTimeout(function () {
                $row.find('.hb-saved-indicator').fadeOut(400, function () { $(this).remove(); });
            }, 3000);
        }
    }

    // Auto-save a single setting; show inline indicator
    function autoSaveSetting(settingName, settingValue, $control) {
        SettingsManager.updateSetting(settingName, settingValue, function (err) {
            showSavedIndicator($control, !err);
            if (err) Toast.error('Failed to save ' + settingName);
        });
    }

    // Debounce helper (utils.js may not be loaded — fallback inline)
    function debounce(fn, ms) {
        var t = null;
        return function () {
            var ctx = this; var args = arguments;
            window.clearTimeout(t);
            t = window.setTimeout(function () { fn.apply(ctx, args); }, ms || 800);
        };
    }

    // Track ONLY alert action config TEXT FIELDS for unsaved-state warning.
    // (Toggles + dropdowns + threshold all auto-save, never "dirty".)
    var dirtyActionConfigs = {}; // { actionType: true } when text input modified since last save

    function isDirty() {
        for (var k in dirtyActionConfigs) if (dirtyActionConfigs[k]) return true;
        return false;
    }

    // Required config fields per alert action type. An action cannot be enabled
    // unless every required field has a non-empty value.
    var REQUIRED_FIELDS = {
        email:      ['recipients'],
        slack:      ['webhook_url'],
        pagerduty:  ['integration_key'],
        teams:      ['webhook_url'],
        webhook:    ['url'],
        servicenow: ['instance', 'username']
    };

    // Fields that must look like an http(s) URL when present (Slack/Teams/
    // generic webhook). Anything else (Slack channel names like "#general",
    // email addresses, bare hostnames) gets surfaced as a field error so the
    // user sees the problem at toggle-time instead of at first alert when the
    // dispatcher rejects the target.
    var URL_FIELDS = {
        slack: ['webhook_url'],
        teams: ['webhook_url'],
        webhook: ['url']
    };

    // Returns array of {field, reason} pairs for invalid/missing fields.
    // Used by both the toggle-ON handler and the per-action Save button.
    function validateActionItem($item) {
        var actionType = $item.data('action');
        var required = REQUIRED_FIELDS[actionType] || [];
        var urlFields = URL_FIELDS[actionType] || [];
        var missing = [];
        required.forEach(function (field) {
            var $input = $item.find('.action-config-input[data-field="' + field + '"]');
            var val = $.trim($input.val() || '');
            if (!val) {
                missing.push(field);
                return;
            }
            if (urlFields.indexOf(field) !== -1 && !/^https?:\/\/\S+$/i.test(val)) {
                missing.push(field + ' (must be a webhook URL like https://...)');
            }
        });
        return missing;
    }

    function markFieldErrors($item, missingFields) {
        $item.find('.action-config-input').removeClass('hb-field-error');
        missingFields.forEach(function (field) {
            // validateActionItem may return "field" or "field (reason)";
            // strip the reason to get the bare data-field selector.
            var bare = String(field).split(' ')[0];
            $item.find('.action-config-input[data-field="' + bare + '"]').addClass('hb-field-error');
        });
    }
    function clearFieldErrors($item) {
        $item.find('.action-config-input').removeClass('hb-field-error');
    }

    // beforeunload — warn user if alert action config text fields have unsaved changes
    window.addEventListener('beforeunload', function (e) {
        if (isDirty()) {
            // Standard pattern; modern browsers ignore custom messages but show their own dialog
            e.preventDefault();
            e.returnValue = 'You have unsaved alert action configuration changes. Leave anyway?';
            return e.returnValue;
        }
    });

    function initEventHandlers() {
        // ========== AUTO-SAVE controls ==========

        // Per-search toggles. Each one targets exactly one saved search so
        // failures are visible and recoverable.
        function makeToggleHandler(searchName, labelId, friendly) {
            return function () {
                var $t = $(this);
                var enabled = $t.is(':checked');
                $('#' + labelId).text(enabled ? 'Enabled' : 'Disabled');
                SavedSearchManager.enableSearchByName(searchName, enabled, function (err) {
                    showSavedIndicator($t, !err);
                    if (err) {
                        // Revert the visual toggle to match the actual server state
                        $t.prop('checked', !enabled);
                        $('#' + labelId).text(!enabled ? 'Enabled' : 'Disabled');
                        // Splunkweb's REST proxy intermittently drops enable POSTs.
                        // Give the user a one-click escape hatch to Splunk's native edit page.
                        var managerUrl = '/en-US/manager/SA-Data-Heartbeat/saved/searches/' +
                            encodeURIComponent(searchName) + '?action=edit';
                        Toast.error(friendly, 9000, { label: 'Edit in Splunk Manager →', href: managerUrl });
                    }
                });
            };
        }
        $(document).on('change', '#setting-enable-detection',
            makeToggleHandler('Data Heartbeat - Source Type Monitor', 'detection-status-label', 'Detection toggle failed'));
        $(document).on('change', '#setting-enable-alert',
            makeToggleHandler('Data Heartbeat Alert - Flagged Sources', 'alert-status-label', 'Alert toggle failed'));
        $(document).on('change', '#setting-enable-discovery',
            makeToggleHandler('Data Heartbeat - Auto Discovery', 'discovery-status-label', 'Discovery toggle failed'));

        // Detection frequency — auto-save on change (also updates cron schedule)
        $(document).on('change', '#setting-detection-frequency', function () {
            var $t = $(this);
            var frequency = $t.val();
            SettingsManager.updateSetting('detection_frequency', frequency, function (err) {
                if (err) { showSavedIndicator($t, false); Toast.error('Failed to save frequency'); return; }
                // Also update the saved-search cron (offset by 1 min from :00 to avoid stampede)
                var cron = '1-59/' + frequency + ' * * * *';
                SavedSearchManager.updateSchedule(cron, function (err2) {
                    showSavedIndicator($t, !err2);
                    if (err2) Toast.error('Schedule update failed');
                });
            });
        });

        // Default threshold — debounced auto-save 800ms after typing stops
        var saveThreshold = debounce(function () {
            var $t = $('#setting-default-threshold');
            var v = parseInt($t.val(), 10);
            if (isNaN(v) || v < 1) { showSavedIndicator($t, false); return; }
            autoSaveSetting('default_threshold', String(v), $t);
        }, 800);
        $(document).on('input change', '#setting-default-threshold', saveThreshold);

        // ========== ALERT ACTIONS ==========

        // Accordion expand/collapse
        $(document).on('click', '.action-accordion-header', function (e) {
            if ($(e.target).closest('.hb-toggle').length) return;
            $(this).closest('.action-accordion-item').toggleClass('expanded');
        });

        // Per-action enable toggle — validate required fields, auto-save, auto-expand
        $(document).on('change', '.action-enabled-toggle', function (e) {
            e.stopPropagation();
            var $t = $(this);
            var $item = $t.closest('.action-accordion-item');
            var actionType = $item.data('action');

            if ($t.is(':checked')) {
                // Enabling — required fields must all be present.
                $item.addClass('expanded');
                var missing = validateActionItem($item);
                if (missing.length > 0) {
                    markFieldErrors($item, missing);
                    $t.prop('checked', false); // revert visual
                    var nice = missing.join(', ');
                    Toast.error(actionType + ': cannot enable — fill in ' + nice + ' first.');
                    // Focus the first missing field
                    $item.find('.action-config-input[data-field="' + missing[0] + '"]').focus();
                    return;
                }
                clearFieldErrors($item);
            }

            collectAlertActionConfigs();
            AlertActionsManager.saveConfigs(function (err) {
                showSavedIndicator($t, !err);
                if (err) Toast.error('Failed to save action toggle');
            });
        });

        // Alert action config text inputs — track dirty state + clear field errors as user types
        $(document).on('input change', '.action-config-input', function () {
            var $input = $(this);
            var $row = $input.closest('.action-accordion-item');
            var actionType = $row.data('action');
            if (actionType) dirtyActionConfigs[actionType] = true;
            // Clear the red border once the user gives this field a value
            if ($.trim($input.val() || '') !== '') {
                $input.removeClass('hb-field-error');
            }
            $row.find('.hb-saved-indicator').remove();
            $row.append('<span class="hb-saved-indicator hb-saved-warn">● Unsaved</span>');
        });

        // "Send Test Alert" button on each accordion — fires a synthetic alert
        // via the custom REST endpoint, which shells out to the dispatcher with
        // a one-row payload. Reports success/failure within ~2 sec.
        $(document).on('click', '.btn-test-action', function () {
            var $btn = $(this);
            var $item = $btn.closest('.action-accordion-item');
            var actionType = $item.data('action');
            var firstField = $item.find('.action-config-input').first();
            var target = $.trim(firstField.val() || '');
            if (!target) {
                Toast.warning('Fill in the config field for ' + actionType + ' first.');
                firstField.focus().addClass('hb-field-error');
                return;
            }
            var origLabel = $btn.html();
            $btn.addClass('hb-loading').html('Sending');
            splunkAjax({
                url: '/en-US/splunkd/__raw/servicesNS/nobody/SA-Data-Heartbeat/data_heartbeat/admin',
                type: 'POST',
                data: { action: 'test_alert', action_type: actionType, target: target },
                complete: function (xhr) {
                    $btn.removeClass('hb-loading').html(origLabel);
                    if (xhr.status >= 200 && xhr.status < 300) {
                        Toast.success('Test alert fired for ' + actionType + '. Check your destination.');
                    } else {
                        var detail = '';
                        try { var j = JSON.parse(xhr.responseText || '{}'); detail = (j.detail && (j.detail.stderr || j.detail.error)) || ''; } catch (e) {}
                        Toast.error('Test alert failed for ' + actionType + (detail ? ': ' + detail.slice(0, 200) : ''));
                    }
                }
            });
        });

        // Per-action Save button — also validates required fields before saving
        $(document).on('click', '.btn-save-action', function () {
            var $btn = $(this);
            var $item = $btn.closest('.action-accordion-item');
            var actionType = $item.data('action');

            // If the action is currently enabled, require its fields to be filled.
            // (Disabling + saving an empty config is allowed.)
            var isEnabled = $item.find('.action-enabled-toggle').is(':checked');
            if (isEnabled) {
                var missing = validateActionItem($item);
                if (missing.length > 0) {
                    markFieldErrors($item, missing);
                    Toast.error(actionType + ': fill in ' + missing.join(', ') + ' before saving.');
                    $item.find('.action-config-input[data-field="' + missing[0] + '"]').focus();
                    return;
                }
                clearFieldErrors($item);
            }

            collectAlertActionConfigs();
            AlertActionsManager.saveConfigs(function (err) {
                if (!err) dirtyActionConfigs[actionType] = false;
                showSavedIndicator($btn, !err);
                if (err) Toast.error('Failed to save ' + actionType);
            });
        });
    }

    // ========================================
    // Initialize
    // ========================================
    // First-run index-access modal: show until the user dismisses with "don't
    // show again". Important because Splunk's | metadata respects the running
    // user's index permissions, and missing index access is the #1 reason
    // sourcetypes get stuck on "Pending".
    function maybeShowIndexAccessModal() {
        var key = 'sa_heartbeat:index_modal_dismissed';
        var dismissed = false;
        try { dismissed = window.localStorage.getItem(key) === '1'; } catch (e) {}
        if (dismissed) return;
        if (window.ModalManager) ModalManager.show('index-access-modal');
        // Persist if the user checks the "don't show again" box
        $(document).off('click.hbIndexModal').on('click.hbIndexModal',
            '#index-access-modal .btn-modal-cancel, #index-access-modal .hb-modal-close',
            function () {
                if ($('#index-modal-dontshow').is(':checked')) {
                    try { window.localStorage.setItem(key, '1'); } catch (e) {}
                }
            }
        );
    }

    function init() {
        console.log('SA-Data-Heartbeat Settings: Initializing...');
        initEventHandlers();
        // Prevent change detection during initial load
        isLoading = true;
        loadSettings();
        loadAlertActions();

        // Capture original values after settings load
        setTimeout(function() {
            captureOriginalValues();
            isLoading = false;
            updateActionBar();
            // Show the index-permissions modal once per user (localStorage flag)
            maybeShowIndexAccessModal();
        }, 1500);
    }

    $(document).ready(init);

    // Expose for debugging and for main page to check configured actions
    window.HeartbeatSettings = {
        AlertActionsManager: AlertActionsManager,
        getConfiguredActions: function() {
            return AlertActionsManager.getConfiguredActions();
        }
    };
});
