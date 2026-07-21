(function($) {

    var ajaxNonce = (typeof won1_ajax !== 'undefined' && won1_ajax.nonce ? won1_ajax.nonce : '');



    /**
     * DOM initialization
     */
    $(function() {
        // Accordion click logic for grouping list elements under categories
        $('.won1-section h3').css('cursor', 'pointer').each(function() {
            var $h3 = $(this);
            if ($h3.find('.dashicons').length === 0) {
                $h3.html('<span class="dashicons dashicons-arrow-down-alt2" style="float:right;margin-top:2px;color:#888;"></span>' + $h3.html());
            }
            $h3.on('click', function() {
                var $table = $h3.next('table');
                var $icon = $h3.find('.dashicons');
                if ($table.length) {
                    if ($table.is(':hidden')) {
                        $table.show();
                        $icon.removeClass('dashicons-arrow-right-alt2').addClass('dashicons-arrow-down-alt2');
                    } else {
                        $table.hide();
                        $icon.removeClass('dashicons-arrow-down-alt2').addClass('dashicons-arrow-right-alt2');
                    }
                }
            });
        });

        // Window hash-change synchronization (backup for inline script)
        $(window).on('hashchange', function() {
            var hash = window.location.hash.replace('#', '');
            if (hash && typeof showTab === 'function') {
                showTab(hash);
            }
        });
    });

})(jQuery);


/* ---- Moved from inline header/settings scripts (v8.1.0, wp_enqueue compliance) ---- */
function won1AddDomains(btn) {
    var ta = document.getElementById("won1-whitelist-textarea");
    if (!ta) return;
    // Drop empty lines first: splitting an empty textarea yields [""] which
    // would otherwise become a stray blank first line after join().
    var existing = ta.value.split("\n").map(function(s){return s.trim();}).filter(function(s){return s.length > 0;});
    var added = 0;
    btn.getAttribute("data-domains").split("|").forEach(function(d) {
        d = d.trim();
        if (d && existing.indexOf(d) === -1) { existing.push(d); added++; }
    });
    if (added) { ta.value = existing.join("\n"); }
}


(function(){
    window.won2_fallback = true;
    var won1_ajaxurl = (window.won1_ajax && window.won1_ajax.ajaxurl) ? window.won1_ajax.ajaxurl : (window.ajaxurl || '/wp-admin/admin-ajax.php');
    var won1_nonce = (window.won1_ajax && window.won1_ajax.nonce) ? window.won1_ajax.nonce : '';

    window.showTab = function(tabId){
        if(!tabId) tabId = 'roster';
        var panels = document.querySelectorAll('.won2-panel');
        for(var i=0; i<panels.length; i++) {
            panels[i].style.setProperty('display', 'none', 'important');
        }
        var tabs = document.querySelectorAll('.nav-tab');
        for(var i=0; i<tabs.length; i++) tabs[i].classList.remove('nav-tab-active');
        var panel = document.getElementById('panel-' + tabId);
        if(panel) {
            panel.style.setProperty('display', 'block', 'important');
        }
        var tabLinks = document.querySelectorAll('a[href="#' + tabId + '"]');
        for(var i=0; i<tabLinks.length; i++) tabLinks[i].classList.add('nav-tab-active');
        if(window.history && window.history.replaceState) window.history.replaceState(null, null, '#' + tabId);
        else window.location.hash = tabId;
        return false;
    };

    window.toggleAllCheckboxes = window.toggleAllCheckboxes || function(master, className) {
        var cbs = document.querySelectorAll('.' + className);
        for(var i=0; i<cbs.length; i++) cbs[i].checked = master.checked;
    };

    window.toggleSection = window.toggleSection || function(id, checked) {
        var section = document.getElementById(id);
        if(section) {
            var cbs = section.querySelectorAll('input[type="checkbox"]');
            for(var i=0; i<cbs.length; i++) cbs[i].checked = checked;
        }
    };

    window.doBulkAction = window.doBulkAction || function(type, action) {
        var cbs = document.querySelectorAll('.cb-' + type + '-core:checked, .cb-' + type + '-theme:checked, .cb-' + type + '-regular:checked, .cb-' + type + '-themes:checked');
        if(cbs.length === 0) { alert('Please select at least one extension.'); return false; }
        var selected = [];
        for(var i=0; i<cbs.length; i++) selected.push(cbs[i].value);
        document.getElementById('bulk-selected-' + type).value = selected.join(',');
        document.getElementById('bulk-action-' + type).value = action;
        return true;
    };

    window.doBulkCronAction = window.doBulkCronAction || function(action) {
        var cbs = document.querySelectorAll('.cron-row-checkbox:checked');
        if(cbs.length === 0) { alert('Please select at least one cron hook.'); return false; }
        var selected = [];
        for(var i=0; i<cbs.length; i++) selected.push(cbs[i].value);
        document.getElementById('bulk-selected-cron').value = selected.join(',');
        document.getElementById('bulk-action-cron').value = action;
        return true;
    };

    window.openDomainModal = function(folder) {
        var modal = document.getElementById('won2-domain-modal');
        var body = document.getElementById('domain-modal-body');
        if(!modal || !body) return;
        modal.style.display = 'block';
        body.innerHTML = '<span class="spinner is-active" style="float:none;"></span> Loading...';

        jQuery.post(won1_ajaxurl, {
            action: 'won2_get_domains',
            nonce: won1_nonce,
            folder: folder
        }, function(res) {
            if(res.success) {
                body.innerHTML = res.data.html;
} else { body.innerHTML = '<p>Error loading domains.</p>'; }
        }).fail(function() { body.innerHTML = '<p>Server error.</p>'; });
    };

    window.closeDomainModal = window.closeDomainModal || function() {
        var modal = document.getElementById('won2-domain-modal');
        if(modal) modal.style.display = 'none';
    };

    window.rewriteMethod = function(folder, method, btn) {
        if (btn.disabled) return;
        btn.disabled = true;
        var originalText = btn.textContent;
        btn.textContent = 'Patching...';

        jQuery.post(won1_ajaxurl, {
            action: 'won2_rewrite_method',
            nonce: won1_nonce,
            folder: folder,
            method: method
        }, function(res) {
            if (res.success) {
                alert(res.data.message || 'Patched successfully.');
                location.reload();
            } else {
                alert('Error: ' + (res.data || 'Failed'));
                btn.disabled = false;
                btn.textContent = originalText;
            }
        }).fail(function() {
            alert('Server error');
            btn.disabled = false;
            btn.textContent = originalText;
        });
    };

    window.restoreMethod = function(folder, method, btn) {
        if (btn.disabled) return;
        btn.disabled = true;
        var originalText = btn.textContent;
        btn.textContent = 'Restoring...';

        jQuery.post(won1_ajaxurl, {
            action: 'won2_restore_method',
            nonce: won1_nonce,
            folder: folder,
            method: method
        }, function(res) {
            if (res.success) {
                alert(res.data.message || 'Restored successfully.');
                location.reload();
            } else {
                alert('Error: ' + (res.data || 'Failed'));
                btn.disabled = false;
                btn.textContent = originalText;
            }
        }).fail(function() {
            alert('Server error');
            btn.disabled = false;
            btn.textContent = originalText;
        });
    };

    window.patchAllExtensions = function() {
        var buttons = document.querySelectorAll('button[data-method][onclick*="rewriteMethod"]');
        if (buttons.length === 0) {
            alert('No unpatched extensions found.');
            return;
        }
        if (!confirm('This will patch ' + buttons.length + ' extension method(s) sequentially. Continue?')) {
            return;
        }

        var spinner = document.getElementById('bulk-cache-spinner');
        var statusText = document.getElementById('bulk-cache-status');
        if (spinner) spinner.classList.add('is-active');

        var index = 0;
        function processNext() {
            if (index >= buttons.length) {
                if (spinner) spinner.classList.remove('is-active');
                if (statusText) statusText.textContent = 'All extensions patched successfully!';
                alert('Sequential patching completed successfully!');
                location.reload();
                return;
            }

            var btn = buttons[index];
            var folder = btn.getAttribute('data-folder');
            var method = btn.getAttribute('data-method');
            if (statusText) {
                statusText.textContent = 'Patching ' + folder + ' (' + method + ')... (' + (index + 1) + '/' + buttons.length + ')';
            }

            jQuery.post(won1_ajaxurl, {
                action: 'won2_rewrite_method',
                nonce: won1_nonce,
                folder: folder,
                method: method
            }, function(res) {
                index++;
                processNext();
            }).fail(function() {
                index++;
                processNext();
            });
        }

        processNext();
    };

    window.won1ToggleObs = function(folder, action, btn) {
        if (btn.disabled) return;
        btn.disabled = true;
        var originalText = btn.textContent;
        btn.textContent = 'Processing...';

        jQuery.post(won1_ajaxurl, {
            action: 'won2_' + action,
            nonce: won1_nonce,
            folder: folder
        }, function(res) {
            if (res.success) {
                alert(res.data.message || 'Updated successfully.');
                location.reload();
            } else {
                alert('Error: ' + (res.data || 'Failed'));
                btn.disabled = false;
                btn.textContent = originalText;
            }
        }).fail(function() {
            alert('Server error');
            btn.disabled = false;
            btn.textContent = originalText;
        });
    };

    window.clearAllCache = function() {
        if(!confirm('Clear all rewritten files across ALL extensions?')) return;
        var spinner = document.getElementById('bulk-cache-spinner');
        if(spinner) spinner.classList.add('is-active');
        jQuery.post(won1_ajaxurl, { action: 'won2_clear_all_cache', nonce: won1_nonce }, function(res) {
            if(res.success) { alert(res.data.message || 'Cleared successfully.'); location.reload(); }
            else { alert('Error: ' + (res.data || 'Failed')); if(spinner) spinner.classList.remove('is-active'); }
        }).fail(function() { alert('Server error'); if(spinner) spinner.classList.remove('is-active'); });
    };

    window.bulkRestoreSelected = function() {
        var cbs = document.querySelectorAll('.curl-cb:checked');
        if(cbs.length === 0) { alert('Select at least one extension to restore.'); return; }
        if(!confirm('Restore selected extensions?')) return;
        var folders = [];
        for(var i=0; i<cbs.length; i++) folders.push(cbs[i].value);
        var spinner = document.getElementById('bulk-cache-spinner');
        if(spinner) spinner.classList.add('is-active');
        jQuery.post(won1_ajaxurl, { action: 'won2_bulk_restore', nonce: won1_nonce, folders: folders }, function(res) {
            if(res.success) { alert(res.data.message || 'Restored successfully.'); location.reload(); }
            else { alert('Error: ' + (res.data || 'Failed')); if(spinner) spinner.classList.remove('is-active'); }
        }).fail(function() { alert('Server error'); if(spinner) spinner.classList.remove('is-active'); });
    };

    document.addEventListener('DOMContentLoaded', function(){
        var urlParams = new URLSearchParams(window.location.search);
        var tabParam = urlParams.get('tab');
        var hash = window.location.hash.replace('#','');
        if(hash && document.getElementById('panel-' + hash)) showTab(hash);
        else if (tabParam && document.getElementById('panel-' + tabParam)) showTab(tabParam);
        else showTab('roster'); 

        var sectionHeaders = document.querySelectorAll('.won1-section h3');
        for(var i=0; i<sectionHeaders.length; i++) {
            sectionHeaders[i].style.cursor = 'pointer';
            sectionHeaders[i].innerHTML = '<span class="dashicons dashicons-arrow-down-alt2" style="float:right;margin-top:2px;color:#888;"></span>' + sectionHeaders[i].innerHTML;
            sectionHeaders[i].addEventListener('click', function(){
                var table = this.nextElementSibling;
                var icon = this.querySelector('.dashicons');
                if(table && table.tagName.toLowerCase() === 'table') {
                    if(table.style.display === 'none') {
                        table.style.display = '';
                        if(icon) { icon.classList.remove('dashicons-arrow-right-alt2'); icon.classList.add('dashicons-arrow-down-alt2'); }
                    } else {
                        table.style.display = 'none';
                        if(icon) { icon.classList.remove('dashicons-arrow-down-alt2'); icon.classList.add('dashicons-arrow-right-alt2'); }
                    }
                }
            });
        }
    });

    window.addEventListener('hashchange', function() {
        var hash = window.location.hash.replace('#','');
        if(hash && document.getElementById('panel-' + hash)) showTab(hash);
    });
})();

        

// Delegated save handler for the per-plugin Domains modal (loaded via AJAX).
jQuery(document).on('click', '.save-domains-btn', function() {
    var btn = this;
    var form = btn.closest('.won2-domain-form');
    if (!form) return;
    var folder = form.getAttribute('data-folder');
    var checks = form.querySelectorAll('input[name="allowed_domains[]"]:checked');
    var domains = [];
    for (var i = 0; i < checks.length; i++) { domains.push(checks[i].value); }
    var notice = document.getElementById('won1-domain-notice');
    var spinner = document.getElementById('won1-save-spinner');
    if (spinner) spinner.style.display = 'inline-block';
    btn.disabled = true;
    var ajax_url = (window.won1_ajax && window.won1_ajax.ajaxurl) ? window.won1_ajax.ajaxurl : (window.ajaxurl || '/wp-admin/admin-ajax.php');
    var ajax_nonce = (window.won1_ajax && window.won1_ajax.nonce) ? window.won1_ajax.nonce : '';
    var data = new FormData();
    data.append('action', 'won2_save_domains');
    data.append('nonce', ajax_nonce);
    data.append('folder', folder);
    for (var k = 0; k < domains.length; k++) { data.append('allowed_domains[]', domains[k]); }
    jQuery.ajax({
        url: ajax_url, type: 'POST', data: data, processData: false, contentType: false,
        success: function(res) {
            if (res && res.success) {
                if (window.closeDomainModal) closeDomainModal();
            } else {
                if (notice) {
                    notice.style.display = 'block';
                    notice.style.background = '#f8d7da';
                    notice.style.color = '#721c24';
                    notice.style.border = '1px solid #dc3545';
                    notice.textContent = 'Error: ' + ((res && res.data) ? res.data : 'Failed');
                }
                btn.disabled = false;
                if (spinner) spinner.style.display = 'none';
            }
        },
        error: function() {
            if (notice) {
                notice.style.display = 'block';
                notice.style.background = '#f8d7da';
                notice.style.color = '#721c24';
                notice.style.border = '1px solid #dc3545';
                notice.textContent = 'Server error';
            }
            btn.disabled = false;
            if (spinner) spinner.style.display = 'none';
        }
    });
});
