/* 
	Enhanced Bot Dashboard JS v2.0.4
	Modern Vanilla JS bot protection interface - FIXED
*/

document.addEventListener('DOMContentLoaded', function() {
	
	// Initialize bot dashboard variables
	var botDashboard = {
		vars: {
			xhr: null,
			count: 0,
			items: [],
			type: 'init',
			bulk: '',
			sort: 'last_seen',
			order: 'desc',
			search: '',
			filter: 'all',
			status: 'all',
			jump: 1,
			offset: 0,
			limit: 10,
			pages: 1,
			toggle: 1,
			fx: 1,
			nonce: window.botDashboard ? window.botDashboard.nonce : '',
			unblock_nonce: window.botDashboard ? window.botDashboard.unblock_nonce : '',
			bulk_nonce: window.botDashboard ? window.botDashboard.bulk_nonce : '',
			ajaxurl: window.botDashboard ? window.botDashboard.ajaxurl : ajaxurl,
			debug: window.botDashboard ? window.botDashboard.debug : false,
			dots: '<span class="bot-loading-dots">Loading</span>'
		}
	};
	
	// Debug logging
	function debugLog(message, data) {
		if (botDashboard.vars.debug) {
			console.log('[Bot Dashboard] ' + message, data || '');
		}
	}
	
	debugLog('Bot Dashboard script loaded');
	debugLog('botDashboard object:', window.botDashboard);
	
	// Check if botDashboard object exists
	if (typeof window.botDashboard === 'undefined') {
		console.error('botDashboard object not found. Script localization failed.');
		showError('Configuration error. Please refresh the page.');
		return;
	}
	
	// Load dashboard stats immediately
	loadBotStats();
	loadBotActivity();
	
	// Auto-refresh every 30 seconds
	setInterval(function() {
		loadBotStats();
		loadBotActivity();
	}, 30000);
	
	// Double-click prevention
	document.ondblclick = function() {
		if (window.getSelection) window.getSelection().removeAllRanges();
		else if (document.selection) document.selection.empty();
	}
	
	// Tools toggle
	var toolsElements = document.querySelectorAll('.bot-tools');
	toolsElements.forEach(function(el) {
		el.style.display = 'none';
	});
	
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-tools-link')) {
			e.preventDefault();
			var tools = document.querySelector('.bot-tools');
			if (tools.style.display === 'none') {
				tools.style.display = 'block';
			} else {
				tools.style.display = 'none';
			}
			e.target.blur();
		}
	});
	
	// Sound effects toggle
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-fx-link')) {
			e.preventDefault();
			if (botDashboard.vars.fx === 0) {
				botDashboard.vars.fx = 1;
				e.target.textContent = e.target.getAttribute('data-fx-on') || 'FX: ON';
			} else {
				botDashboard.vars.fx = 0;
				e.target.textContent = e.target.getAttribute('data-fx-off') || 'FX: OFF';
			}
			botDashboard.vars.type = 'items';
			loadBotActivity();
			e.target.blur();
		}
	});
	
	// Row hover effects
	document.addEventListener('mouseenter', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-row')) {
			var selectTarget = e.target.querySelector('.bot-select-target');
			if (selectTarget) {
				selectTarget.classList.add('bot-visible');
			}
		}
	}, true);
	
	document.addEventListener('mouseleave', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-row')) {
			var selectTarget = e.target.querySelector('.bot-select-target');
			if (selectTarget) {
				selectTarget.classList.remove('bot-visible');
			}
		}
	}, true);
	
	// Toggle detailed view
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-toggle-link')) {
			e.preventDefault();
			if (botDashboard.vars.toggle == 2) {
				e.target.textContent = e.target.getAttribute('data-view-adv') || 'View Advanced';
				var dataElements = document.querySelectorAll('.bot-data');
				dataElements.forEach(function(el) {
					el.style.display = 'none';
				});
				botDashboard.vars.toggle = 1;
				var requestLinks = document.querySelectorAll('.bot-request a');
				requestLinks.forEach(function(link) {
					var request = link.getAttribute('data-request');
					var req = request.substring(0, 50) + '...';
					if (request.length > 50) {
						link.textContent = req;
						link.style.display = 'inline';
					}
				});
			} else {
				e.target.textContent = e.target.getAttribute('data-view-bsc') || 'View Basic';
				var dataElements = document.querySelectorAll('.bot-data');
				dataElements.forEach(function(el) {
					el.style.display = 'block';
				});
				botDashboard.vars.toggle = 2;
				var requestLinks = document.querySelectorAll('.bot-request a');
				requestLinks.forEach(function(link) {
					var request = link.getAttribute('data-request');
					link.textContent = request;
					link.style.display = 'inline';
				});
			}
			botDashboard.vars.type = 'items';
			loadBotActivity();
			e.target.blur();
		}
	});
	
	// Double-click to toggle details
	document.addEventListener('dblclick', function(e) {
		if (e.target && e.target.closest('.bot-row')) {
			e.preventDefault();
			var row = e.target.closest('.bot-row');
			var data = row.querySelector('.bot-data');
			var current = row.querySelector('.bot-request a');
			var request = current.getAttribute('data-request');
			var req = request.substring(0, 50) + '...';
			
			if (data.style.display === 'block') {
				if (request.length > 50) {
					current.textContent = req;
					current.style.display = 'inline';
				}
				data.style.display = 'none';
			} else {
				current.textContent = request;
				current.style.display = 'inline';
				data.style.display = 'block';
			}
		}
	});
	
	// Host lookup
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-hostlookup-link')) {
			e.preventDefault();
			var id = e.target.getAttribute('data-id');
			var ip = e.target.getAttribute('data-ip');
			var lookupElement = document.querySelector('.bot-hostlookup-id-' + id);
			if (lookupElement) {
				lookupElement.innerHTML = botDashboard.vars.dots;
			}
			performHostLookup(id, ip);
			e.target.blur();
		}
	});
	
	// Reload functionality
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && (e.target.classList.contains('bot-addvisit-link') || e.target.classList.contains('bot-reload-link'))) {
			e.preventDefault();
			clearBotData();
			botDashboard.vars.type = 'init';
			if (e.target.classList.contains('bot-addvisit-link')) {
				botDashboard.vars.type = 'add';
			}
			loadBotActivity();
			e.target.blur();
		}
	});
	
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-reload-current')) {
			e.preventDefault();
			botDashboard.vars.type = 'init';
			loadBotActivity();
			e.target.blur();
		}
	});
	
	// Delete functionality
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-delete-link')) {
			e.preventDefault();
			e.target.blur();
			
			if (confirm('Are you sure you want to delete all selected items?')) {
				clearBotData();
				botDashboard.vars.type = 'delete';
				if (botDashboard.vars.fx === 1) {
					playSound('delete');
				}
				loadBotActivity();
			}
		}
	});
	
	// Select all functionality
	document.addEventListener('change', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-select-all')) {
			var botIds = document.querySelectorAll('.bot-id');
			botIds.forEach(function(checkbox) {
				checkbox.checked = e.target.checked;
			});
		}
	});
	
	document.addEventListener('change', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-id')) {
			var uncheckedBoxes = document.querySelectorAll('.bot-id:not(:checked)');
			var selectAll = document.querySelector('.bot-select-all');
			if (selectAll) {
				selectAll.checked = uncheckedBoxes.length === 0;
			}
		}
	});
	
	// Bulk actions
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-action-bulk')) {
			e.preventDefault();
			var bulkSelect = document.querySelector('.bot-select-bulk');
			var bulk = bulkSelect ? bulkSelect.value : '';
			var items = [];
			var checkedBoxes = document.querySelectorAll('.bot-id:checked');
			
			checkedBoxes.forEach(function(checkbox) {
				if (bulk == 'delete') {
					botDashboard.vars.count = botDashboard.vars.count - 1;
				}
				items.push(checkbox.value);
			});
			
			if (botDashboard.vars.offset == botDashboard.vars.count) {
				botDashboard.vars.offset = Math.abs(botDashboard.vars.offset - botDashboard.vars.limit);
			}
			var jump = Math.ceil(botDashboard.vars.offset / botDashboard.vars.limit) + 1;
			
			if (botDashboard.vars.fx === 1 && bulk == 'delete') {
				playSound('delete');
			}
			
			botDashboard.vars.jump = jump;
			botDashboard.vars.bulk = bulk;
			botDashboard.vars.items = items;
			botDashboard.vars.type = 'bulk';
			loadBotActivity();
			e.target.blur();
		}
	});
	
	// Individual actions (Ban, Warn, Restore, etc.) - FIXED
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && 
			(e.target.classList.contains('bot-action-ban') || 
			e.target.classList.contains('bot-action-warn') || 
			e.target.classList.contains('bot-action-restore') || 
			e.target.classList.contains('bot-action-whitelist') || 
			e.target.classList.contains('bot-action-delete'))) {
			
			e.preventDefault();
			
			// FIXED: Use data-bot-action instead of data-action
			var action = e.target.getAttribute('data-bot-action');
			var id = e.target.getAttribute('data-id');
			var ip = e.target.getAttribute('data-ip');
			
			debugLog('Action clicked:', {action: action, id: id, ip: ip});
			
			if (!action || !id) {
				showError('Missing action or ID data');
				return;
			}
			
			// Confirm action
			var actionText = action.charAt(0).toUpperCase() + action.slice(1);
			if (!confirm('Are you sure you want to ' + actionText + ' this IP: ' + ip + '?')) {
				return;
			}
			
			// Disable button during request
			e.target.disabled = true;
			e.target.classList.add('processing');
			
			// Perform bulk action via AJAX
			var xhr = new XMLHttpRequest();
			xhr.open('POST', botDashboard.vars.ajaxurl, true);
			xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			
			xhr.onreadystatechange = function() {
				if (xhr.readyState === 4) {
					e.target.disabled = false;
					e.target.classList.remove('processing');
					
					if (xhr.status === 200) {
						try {
							var response = JSON.parse(xhr.responseText);
							debugLog('Bulk action response:', response);
							
							if (response && response.success) {
								showNotice(response.data, 'success');
								
								// Play sound effect
								if (botDashboard.vars.fx === 1) {
									playSound(action);
								}
								
								// Reload activity to show changes
								loadBotActivity();
								loadBotStats();
							} else {
								var errorMsg = response && response.data ? response.data : 'Unknown error';
								showNotice('Failed to ' + actionText + ': ' + errorMsg, 'error');
							}
						} catch (e) {
							showNotice('Failed to parse response', 'error');
						}
					} else {
						debugLog('Bulk action AJAX error:', {status: xhr.status, responseText: xhr.responseText});
						showNotice('Error occurred while performing action: HTTP ' + xhr.status, 'error');
					}
				}
			};
			
			// FIXED: Send bot_action instead of action
			var params = 'action=bot_blocker_bulk_action&nonce=' + encodeURIComponent(botDashboard.vars.bulk_nonce) + 
						 '&bot_action=' + encodeURIComponent(action) + 
						 '&id=' + encodeURIComponent(id) + 
						 '&ip=' + encodeURIComponent(ip);
			
			xhr.send(params);
			e.target.blur();
		}
	});
	
	// Unblock bot functionality
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('unblock-bot')) {
			var ip = e.target.getAttribute('data-ip');
			var button = e.target;
			
			if (!ip) {
				showError('Invalid IP address');
				return;
			}
			
			if (!confirm('Are you sure you want to unblock IP: ' + ip + '?')) {
				return;
			}
			
			button.disabled = true;
			button.textContent = 'Unblocking...';
			
			debugLog('Unblocking IP:', ip);
			
			var xhr = new XMLHttpRequest();
			xhr.open('POST', botDashboard.vars.ajaxurl, true);
			xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			
			xhr.onreadystatechange = function() {
				if (xhr.readyState === 4) {
					if (xhr.status === 200) {
						try {
							var response = JSON.parse(xhr.responseText);
							debugLog('Unblock response:', response);
							
							if (response && response.success) {
								var row = button.closest('tr');
								if (row) {
									row.style.opacity = '0';
									setTimeout(function() {
										row.remove();
									}, 300);
								}
								showNotice('IP unblocked successfully', 'success');
								// Reload stats after unblocking
								loadBotStats();
								loadBotActivity();
							} else {
								var errorMsg = response && response.data ? response.data : 'Unknown error';
								showNotice('Failed to unblock IP: ' + errorMsg, 'error');
								button.disabled = false;
								button.textContent = 'Unblock';
							}
						} catch (e) {
							showNotice('Failed to parse response', 'error');
							button.disabled = false;
							button.textContent = 'Unblock';
						}
					} else {
						debugLog('Unblock AJAX error:', {status: xhr.status, responseText: xhr.responseText});
						showNotice('Error occurred while unblocking IP: HTTP ' + xhr.status, 'error');
						button.disabled = false;
						button.textContent = 'Unblock';
					}
				}
			};
			
			var params = 'action=bot_blocker_unblock&nonce=' + encodeURIComponent(botDashboard.vars.unblock_nonce) + 
						 '&ip=' + encodeURIComponent(ip);
			
			xhr.send(params);
		}
	});
	
	// Pagination
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-page-next')) {
			e.preventDefault();
			if (botDashboard.vars.offset < botDashboard.vars.count) {
				botDashboard.vars.offset = botDashboard.vars.offset + botDashboard.vars.limit;
				botDashboard.vars.jump = botDashboard.vars.jump + 1;
				botDashboard.vars.type = 'next';
				loadBotActivity();
			}
			e.target.blur();
		}
	});
	
	document.addEventListener('click', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-page-prev')) {
			e.preventDefault();
			if (botDashboard.vars.offset > 0) {
				botDashboard.vars.offset = botDashboard.vars.offset - botDashboard.vars.limit;
				botDashboard.vars.jump = botDashboard.vars.jump - 1;
				botDashboard.vars.type = 'prev';
				loadBotActivity();
			}
			e.target.blur();
		}
	});
	
	document.addEventListener('keypress', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-page-jump')) {
			if (e.keyCode === 13 || e.which === 13) {
				e.preventDefault();
				var jump = parseInt(e.target.value);
				if (jump <= 0) jump = 1;
				if (jump > botDashboard.vars.pages) jump = botDashboard.vars.pages;
				botDashboard.vars.offset = (jump - 1) * botDashboard.vars.limit;
				botDashboard.vars.jump = jump;
				botDashboard.vars.type = 'jump';
				loadBotActivity();
			}
		}
	});
	
	// Items per page
	var hoverInfo = document.querySelector('.bot-hover-info');
	if (hoverInfo) {
		hoverInfo.style.display = 'none';
	}
	
	document.addEventListener('mouseenter', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-page-items')) {
			var hoverInfo = document.querySelector('.bot-hover-info');
			if (hoverInfo) {
				hoverInfo.style.display = 'inline-block';
			}
		}
	});
	
	document.addEventListener('mouseleave', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-page-items')) {
			var hoverInfo = document.querySelector('.bot-hover-info');
			if (hoverInfo) {
				hoverInfo.style.display = 'none';
			}
		}
	});
	
	document.addEventListener('keypress', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-page-items')) {
			if (e.keyCode === 13 || e.which === 13) {
				e.preventDefault();
				var limit_new = parseInt(e.target.value);
				var limit_old = parseInt(e.target.getAttribute('data-limit'));
				if (limit_new <= 0) {
					limit_new = limit_old;
					e.target.value = limit_old;
				}
				if (limit_new > 50) {
					if (confirm('Large numbers of rows may impact performance. Continue?')) {
						botDashboard.vars.limit = limit_new;
						botDashboard.vars.offset = 0;
						botDashboard.vars.jump = 1;
						botDashboard.vars.type = 'items';
						loadBotActivity();
					} else {
						e.target.value = limit_old;
					}
				} else {
					botDashboard.vars.limit = limit_new;
					botDashboard.vars.offset = 0;
					botDashboard.vars.jump = 1;
					botDashboard.vars.type = 'items';
					loadBotActivity();
				}
			}
		}
	});
	
	// Search and filter
	document.addEventListener('keypress', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-action-search')) {
			if (e.keyCode === 13 || e.which === 13) {
				e.preventDefault();
				var search = e.target.value;
				var filterSelect = document.querySelector('.bot-select-filter');
				var filter = filterSelect ? filterSelect.value : '';
				performSearch(search, filter);
			}
		}
	});
	
	document.addEventListener('change', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-select-filter')) {
			e.preventDefault();
			var searchInput = document.querySelector('.bot-action-search');
			var search = searchInput ? searchInput.value : '';
			var filter = e.target.value;
			if (search) {
				performSearch(search, filter);
			}
		}
	});
	
	function performSearch(search, filter) {
		if (!filter) filter = '';
		botDashboard.vars.search = search;
		botDashboard.vars.filter = filter;
		botDashboard.vars.offset = 0;
		botDashboard.vars.count = 0;
		botDashboard.vars.jump = 1;
		botDashboard.vars.type = 'search';
		loadBotActivity();
	}
	
	// Sort and order
	document.addEventListener('change', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && (e.target.classList.contains('bot-select-sort') || e.target.classList.contains('bot-select-order'))) {
			e.preventDefault();
			var sortSelect = document.querySelector('.bot-select-sort');
			var orderSelect = document.querySelector('.bot-select-order');
			var sort = sortSelect ? sortSelect.value : 'last_seen';
			var order = orderSelect ? orderSelect.value : 'desc';
			if (!sort) sort = 'last_seen';
			if (!order) order = 'desc';
			botDashboard.vars.sort = sort;
			botDashboard.vars.order = order;
			botDashboard.vars.type = 'sort';
			loadBotActivity();
			e.target.blur();
		}
	});
	
	// Status filter
	document.addEventListener('change', function(e) {
		// FIXED: Check if e.target exists and has classList
		if (e.target && e.target.classList && e.target.classList.contains('bot-select-status')) {
			e.preventDefault();
			var status = e.target.value;
			if (!status) status = 'all';
			botDashboard.vars.offset = 0;
			botDashboard.vars.count = 0;
			botDashboard.vars.jump = 1;
			botDashboard.vars.type = 'status';
			botDashboard.vars.status = status;
			loadBotActivity();
			e.target.blur();
		}
	});
	
	// Core Functions
	function performHostLookup(id, ip) {
		if (botDashboard.vars.xhr != null) {
			botDashboard.vars.xhr.abort();
			botDashboard.vars.xhr = null;
		}
		
		var xhr = new XMLHttpRequest();
		xhr.open('POST', botDashboard.vars.ajaxurl, true);
		xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		
		xhr.onreadystatechange = function() {
			if (xhr.readyState === 4 && xhr.status === 200) {
				var lookupElement = document.querySelector('.bot-hostlookup-id-' + id);
				if (lookupElement) {
					lookupElement.innerHTML = xhr.responseText;
				}
			}
		};
		
		var params = 'action=bot_hostlookup&nonce=' + encodeURIComponent(botDashboard.vars.nonce) + 
					 '&id=' + encodeURIComponent(id) + 
					 '&ip=' + encodeURIComponent(ip);
		
		botDashboard.vars.xhr = xhr;
		xhr.send(params);
	}
	
	function loadBotActivity() {
		prepareBotActivity();
		if (botDashboard.vars.xhr != null) {
			botDashboard.vars.xhr.abort();
			botDashboard.vars.xhr = null;
		}
		
		var xhr = new XMLHttpRequest();
		xhr.open('POST', botDashboard.vars.ajaxurl, true);
		xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		
		xhr.onreadystatechange = function() {
			if (xhr.readyState === 4) {
				if (xhr.status === 200) {
					processBotResponse(xhr.responseText);
					updateBotUI();
				} else {
					debugLog('Activity AJAX error:', {status: xhr.status, responseText: xhr.responseText});
					showError('Failed to load bot activity: HTTP ' + xhr.status);
					setErrorValues();
				}
			}
		};
		
		var params = 'action=bot_blocker_activity&nonce=' + encodeURIComponent(botDashboard.vars.nonce) + 
					 '&items=' + encodeURIComponent(JSON.stringify(botDashboard.vars.items)) + 
					 '&type=' + encodeURIComponent(botDashboard.vars.type) + 
					 '&bulk=' + encodeURIComponent(botDashboard.vars.bulk) + 
					 '&sort=' + encodeURIComponent(botDashboard.vars.sort) + 
					 '&order=' + encodeURIComponent(botDashboard.vars.order) + 
					 '&search=' + encodeURIComponent(botDashboard.vars.search) + 
					 '&filter=' + encodeURIComponent(botDashboard.vars.filter) + 
					 '&status=' + encodeURIComponent(botDashboard.vars.status) + 
					 '&jump=' + encodeURIComponent(botDashboard.vars.jump) + 
					 '&count=' + encodeURIComponent(botDashboard.vars.count) + 
					 '&limit=' + encodeURIComponent(botDashboard.vars.limit) + 
					 '&offset=' + encodeURIComponent(botDashboard.vars.offset) + 
					 '&toggle=' + encodeURIComponent(botDashboard.vars.toggle) + 
					 '&fx=' + encodeURIComponent(botDashboard.vars.fx);
		
		botDashboard.vars.xhr = xhr;
		xhr.send(params);
	}
	
	function prepareBotActivity() {
		var armory = document.querySelector('.bot-armory');
		if (armory) {
			armory.style.display = 'block';
		}
		
		var response = document.querySelector('.bot-response');
		if (response) {
			response.innerHTML = '';
		}
		
		var loading = document.querySelector('.bot-loading');
		if (loading) {
			loading.style.display = 'block';
		}
		
		var tools = document.querySelector('.bot-tools');
		if (tools) {
			if (tools.style.display === 'block') {
				tools.style.display = 'block';
			} else {
				tools.style.display = 'none';
			}
		}
		
		if (botDashboard.vars.type != 'bulk' && botDashboard.vars.search != '') {
			botDashboard.vars.type = 'search';
		}
	}
	
	function processBotResponse(data) {
		var tempDiv = document.createElement('div');
		tempDiv.innerHTML = data;
		
		var countDiv = tempDiv.querySelector('.bot-count-data');
		var count = 0;
		if (countDiv) {
			count = parseInt(countDiv.getAttribute('data-count')) || 0;
		}
		botDashboard.vars.count = count;
		
		var loading = document.querySelector('.bot-loading');
		if (loading) {
			loading.style.display = 'none';
		}
		
		if (botDashboard.vars.type == 'delete') {
			var tools = document.querySelector('.bot-tools');
			if (tools) {
				tools.style.display = 'none';
			}
		}
		
		var countElement = document.querySelector('.bot-count');
		if (countElement && countDiv) {
			countElement.innerHTML = countDiv.innerHTML;
		}
		
		var response = document.querySelector('.bot-response');
		if (response) {
			response.innerHTML = '';
		}
		
		if (count > 0) {
			var rows = tempDiv.querySelectorAll('.bot-row');
			rows.forEach(function(row, i) {
				row.style.opacity = '0';
				if (response) {
					response.appendChild(row);
				}
				
				setTimeout(function() {
					row.style.opacity = '1';
				}, (i + 1) * 50);
				
				if (botDashboard.vars.toggle == 2) {
					var toggleLink = document.querySelector('.bot-toggle-link');
					if (toggleLink) {
						toggleLink.textContent = toggleLink.getAttribute('data-view-bsc') || 'View Basic';
					}
					var dataElement = row.querySelector('.bot-data');
					if (dataElement) {
						dataElement.style.display = 'block';
					}
					var requestLinks = row.querySelectorAll('.bot-request a');
					requestLinks.forEach(function(link) {
						var request = link.getAttribute('data-request');
						link.textContent = request;
						link.style.display = 'inline';
					});
				} else {
					var toggleLink = document.querySelector('.bot-toggle-link');
					if (toggleLink) {
						toggleLink.textContent = toggleLink.getAttribute('data-view-adv') || 'View Advanced';
					}
					var dataElement = row.querySelector('.bot-data');
					if (dataElement) {
						dataElement.style.display = 'none';
					}
					var requestLinks = row.querySelectorAll('.bot-request a');
					requestLinks.forEach(function(link) {
						var request = link.getAttribute('data-request');
						var req = request.substring(0, 50) + '...';
						if (request.length > 50) {
							link.textContent = req;
							link.style.display = 'inline';
						}
					});
				}
				
				var selectTarget = row.querySelector('.bot-select-target');
				if (selectTarget) {
					selectTarget.classList.remove('bot-visible');
				}
				
				var dateElement = row.querySelector('.bot-date');
				if (dateElement) {
					var dateHtml = dateElement.innerHTML.replace(/@/gi, '<span class="bot-at">@</span>');
					dateElement.innerHTML = dateHtml;
				}
			});
			
			if (response) {
				var height = response.offsetHeight;
				if (loading) {
					loading.style.minHeight = height + 'px';
				}
			}
		} else {
			if (countDiv && response) {
				countDiv.style.opacity = '0';
				response.appendChild(countDiv);
				setTimeout(function() {
					countDiv.style.opacity = '1';
				}, 50);
			}
			if (loading) {
				loading.style.minHeight = '80px';
			}
		}
		
		var fxLink = document.querySelector('.bot-fx-link');
		if (fxLink) {
			if (botDashboard.vars.fx === 0) {
				fxLink.textContent = fxLink.getAttribute('data-fx-off') || 'FX: OFF';
			} else {
				fxLink.textContent = fxLink.getAttribute('data-fx-on') || 'FX: ON';
			}
		}
	}
	
	function updateBotUI() {
		botDashboard.vars.pages = Math.ceil(botDashboard.vars.count / botDashboard.vars.limit);
		if (botDashboard.vars.pages === 0) botDashboard.vars.pages = 1;
		
		var nextButton = document.querySelector('.bot-page-next');
		if (nextButton) {
			if ((botDashboard.vars.count - botDashboard.vars.offset) <= botDashboard.vars.limit) {
				nextButton.disabled = true;
			} else {
				nextButton.disabled = false;
			}
		}
		
		var prevButton = document.querySelector('.bot-page-prev');
		if (prevButton) {
			if (botDashboard.vars.offset > 0) {
				prevButton.disabled = false;
			} else {
				prevButton.disabled = true;
			}
		}
		
		var paging = document.querySelector('.bot-paging');
		if (paging) {
			if (botDashboard.vars.count === 0) {
				paging.style.display = 'none';
			} else {
				paging.style.display = 'block';
			}
		}
		
		var pageItems = document.querySelector('.bot-page-items');
		if (pageItems) {
			pageItems.setAttribute('data-limit', botDashboard.vars.limit);
		}
		
		var bulkSelect = document.querySelector('.bot-select-bulk');
		if (bulkSelect) {
			bulkSelect.value = '';
		}
		
		var sortSelect = document.querySelector('.bot-select-sort');
		if (sortSelect) {
			sortSelect.value = botDashboard.vars.sort;
		}
		
		var orderSelect = document.querySelector('.bot-select-order');
		if (orderSelect) {
			orderSelect.value = botDashboard.vars.order;
		}
		
		var searchInput = document.querySelector('.bot-action-search');
		if (searchInput) {
			searchInput.value = botDashboard.vars.search;
		}
		
		var filterSelect = document.querySelector('.bot-select-filter');
		if (filterSelect) {
			filterSelect.value = botDashboard.vars.filter;
		}
		
		var statusSelect = document.querySelector('.bot-select-status');
		if (statusSelect) {
			statusSelect.value = botDashboard.vars.status;
		}
		
		var jumpInput = document.querySelector('.bot-page-jump');
		if (jumpInput) {
			jumpInput.value = botDashboard.vars.jump;
		}
		
		var totalSpan = document.querySelector('.bot-page-total');
		if (totalSpan) {
			totalSpan.textContent = botDashboard.vars.pages;
		}
		
		var selectAll = document.querySelector('.bot-select-all');
		if (selectAll) {
			selectAll.checked = false;
		}
	}
	
	function clearBotData() {
		botDashboard.vars.count = 0;
		botDashboard.vars.items = [];
		botDashboard.vars.type = 'init';
		botDashboard.vars.bulk = '';
		botDashboard.vars.sort = 'last_seen';
		botDashboard.vars.order = 'desc';
		botDashboard.vars.search = '';
		botDashboard.vars.filter = 'all';
		botDashboard.vars.status = 'all';
		botDashboard.vars.jump = 1;
		botDashboard.vars.offset = 0;
		var searchInput = document.querySelector('.bot-action-search');
		if (searchInput) {
			searchInput.value = '';
		}
	}
	
	function loadBotStats() {
		debugLog('Loading bot stats...');
		
		var xhr = new XMLHttpRequest();
		xhr.open('POST', botDashboard.vars.ajaxurl, true);
		xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		
		xhr.onreadystatechange = function() {
			if (xhr.readyState === 4) {
				if (xhr.status === 200) {
					try {
						var response = JSON.parse(xhr.responseText);
						debugLog('Stats response:', response);
						
						if (response && response.success && response.data) {
							var data = response.data;
							
							// Update stats with fallback values
							var totalBlocked = document.getElementById('total-blocked');
							if (totalBlocked) {
								totalBlocked.textContent = data.total_blocked || 0;
							}
							
							var todayBlocked = document.getElementById('today-blocked');
							if (todayBlocked) {
								todayBlocked.textContent = data.today_blocked || 0;
							}
							
							var weekBlocked = document.getElementById('week-blocked');
							if (weekBlocked) {
								weekBlocked.textContent = data.week_blocked || 0;
							}
							
							// Update top blocked IPs
							var topBlockedHtml = '<ul class="top-blocked-list">';
							if (data.top_blocked_ips && data.top_blocked_ips.length > 0) {
								data.top_blocked_ips.forEach(function(item) {
									topBlockedHtml += '<li>';
									topBlockedHtml += '<span class="ip-address">' + escapeHtml(item.ip_address) + '</span>';
									topBlockedHtml += '<span class="hit-count">' + (item.hits || 0) + ' hits</span>';
									topBlockedHtml += '</li>';
								});
							} else {
								topBlockedHtml += '<li>No blocked IPs found</li>';
							}
							topBlockedHtml += '</ul>';
							
							var topBlockedElement = document.getElementById('top-blocked-ips');
							if (topBlockedElement) {
								topBlockedElement.innerHTML = topBlockedHtml;
							}
						} else {
							var errorMsg = response && response.data ? response.data : 'Unknown error';
							console.error('Failed to load bot stats:', errorMsg);
							setErrorValues();
						}
					} catch (e) {
						console.error('Failed to parse stats response:', e);
						setErrorValues();
					}
				} else {
					debugLog('Stats AJAX error:', {status: xhr.status, responseText: xhr.responseText});
					
					var errorMsg = 'Failed to load statistics';
					if (xhr.responseText) {
						// Check if response is HTML (likely an error page)
						if (xhr.responseText.indexOf('<') === 0) {
							errorMsg += ' (Server returned HTML instead of JSON - check for PHP errors)';
							console.error('Server response:', xhr.responseText.substring(0, 200) + '...');
						} else {
							try {
								var response = JSON.parse(xhr.responseText);
								if (response.data) {
									errorMsg += ': ' + response.data;
								}
							} catch (e) {
								errorMsg += ': HTTP ' + xhr.status;
							}
						}
					} else {
						errorMsg += ': HTTP ' + xhr.status;
					}
					
					console.error('AJAX Error loading stats:', errorMsg);
					setErrorValues();
					showError(errorMsg);
				}
			}
		};
		
		var params = 'action=bot_blocker_stats&nonce=' + encodeURIComponent(botDashboard.vars.nonce);
		xhr.send(params);
	}
	
	function setErrorValues() {
		var totalBlocked = document.getElementById('total-blocked');
		if (totalBlocked) {
			totalBlocked.textContent = 'Error';
		}
		
		var todayBlocked = document.getElementById('today-blocked');
		if (todayBlocked) {
			todayBlocked.textContent = 'Error';
		}
		
		var weekBlocked = document.getElementById('week-blocked');
		if (weekBlocked) {
			weekBlocked.textContent = 'Error';
		}
		
		var topBlockedElement = document.getElementById('top-blocked-ips');
		if (topBlockedElement) {
			topBlockedElement.innerHTML = '<ul class="top-blocked-list"><li>Error loading data</li></ul>';
		}
	}
	
	function showNotice(message, type) {
		var noticeClass = type === 'success' ? 'notice-success' : 'notice-error';
		var notice = document.createElement('div');
		notice.className = 'notice ' + noticeClass + ' is-dismissible';
		notice.innerHTML = '<p>' + escapeHtml(message) + '</p>';
		
		var h1 = document.querySelector('.wrap h1');
		if (h1) {
			h1.parentNode.insertBefore(notice, h1.nextSibling);
		}
		
		setTimeout(function() {
			notice.style.opacity = '0';
			setTimeout(function() {
				if (notice.parentNode) {
					notice.parentNode.removeChild(notice);
				}
			}, 300);
		}, 5000);
	}
	
	function showError(message) {
		showNotice(message, 'error');
	}
	
	function escapeHtml(text) {
		var map = {
			'&': '&amp;',
			'<': '&lt;',
			'>': '&gt;',
			'"': '&quot;',
			"'": '&#039;'
		};
		return text.replace(/[&<>"']/g, function(m) { return map[m]; });
	}
	
	function playSound(action) {
		// Simple sound effect simulation using Web Audio API
		if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
			var audioContext = new (window.AudioContext || window.webkitAudioContext)();
			var oscillator = audioContext.createOscillator();
			var gainNode = audioContext.createGain();
			
			oscillator.connect(gainNode);
			gainNode.connect(audioContext.destination);
			
			var frequency = 440; // Default frequency
			switch(action) {
				case 'ban':
					frequency = 200; // Low tone for ban
					break;
				case 'warn':
					frequency = 600; // Mid tone for warn
					break;
				case 'restore':
					frequency = 800; // High tone for restore
					break;
				case 'delete':
					frequency = 150; // Very low tone for delete
					break;
			}
			
			oscillator.frequency.setValueAtTime(frequency, audioContext.currentTime);
			oscillator.type = 'sine';
			
			gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
			gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
			
			oscillator.start(audioContext.currentTime);
			oscillator.stop(audioContext.currentTime + 0.3);
		}
	}
});