/**
 * CYBERDUDEBIVASH SENTINEL APEX — Client-Side Watchlist & Saved Searches
 *
 * Real, working anonymous-first feature: saved searches and a watchlist
 * (CVEs/vendors/actors/etc.) stored in browser localStorage — no server
 * identity system required. Storage is injectable so this is testable
 * outside a browser; defaults to window.localStorage when available.
 * Fails silently (never throws into caller UI code) if storage is
 * unavailable or quota-exceeded — a broken save should never break the
 * page around it.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelWatchlist = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SEARCHES_KEY = 'sentinel_saved_searches';
  var WATCHLIST_KEY = 'sentinel_watchlist';
  var MAX_SEARCHES = 20;
  var MAX_WATCHLIST = 50;

  function defaultStorage() {
    if (typeof localStorage !== 'undefined') return localStorage;
    return null;
  }

  function readList(storage, key) {
    storage = storage || defaultStorage();
    if (!storage) return [];
    try {
      var raw = storage.getItem(key);
      var parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  function writeList(storage, key, list) {
    storage = storage || defaultStorage();
    if (!storage) return false;
    try {
      storage.setItem(key, JSON.stringify(list));
      return true;
    } catch (e) {
      return false; // quota exceeded / storage disabled — caller can ignore the false return
    }
  }

  function getSavedSearches(storage) {
    return readList(storage, SEARCHES_KEY);
  }

  function saveSearch(query, typeFilter, storage) {
    query = String(query || '').trim();
    typeFilter = typeFilter || 'ALL';
    if (!query) return getSavedSearches(storage);
    var list = getSavedSearches(storage).filter(function (s) {
      return !(s.query === query && s.typeFilter === typeFilter);
    });
    list.unshift({ query: query, typeFilter: typeFilter, savedAt: new Date().toISOString() });
    list = list.slice(0, MAX_SEARCHES);
    writeList(storage, SEARCHES_KEY, list);
    return list;
  }

  function removeSavedSearch(query, typeFilter, storage) {
    var list = getSavedSearches(storage).filter(function (s) {
      return !(s.query === query && s.typeFilter === typeFilter);
    });
    writeList(storage, SEARCHES_KEY, list);
    return list;
  }

  function getWatchlist(storage) {
    return readList(storage, WATCHLIST_KEY);
  }

  function isInWatchlist(type, id, storage) {
    return getWatchlist(storage).some(function (item) {
      return item.type === type && item.id === id;
    });
  }

  function addToWatchlist(item, storage) {
    if (!item || !item.type || !item.id) return getWatchlist(storage);
    var list = getWatchlist(storage).filter(function (i) {
      return !(i.type === item.type && i.id === item.id);
    });
    list.unshift({
      type: item.type,
      id: item.id,
      label: item.label || item.id,
      url: item.url || null,
      addedAt: new Date().toISOString(),
    });
    list = list.slice(0, MAX_WATCHLIST);
    writeList(storage, WATCHLIST_KEY, list);
    return list;
  }

  function removeFromWatchlist(type, id, storage) {
    var list = getWatchlist(storage).filter(function (i) {
      return !(i.type === type && i.id === id);
    });
    writeList(storage, WATCHLIST_KEY, list);
    return list;
  }

  return {
    SEARCHES_KEY: SEARCHES_KEY,
    WATCHLIST_KEY: WATCHLIST_KEY,
    MAX_SEARCHES: MAX_SEARCHES,
    MAX_WATCHLIST: MAX_WATCHLIST,
    getSavedSearches: getSavedSearches,
    saveSearch: saveSearch,
    removeSavedSearch: removeSavedSearch,
    getWatchlist: getWatchlist,
    addToWatchlist: addToWatchlist,
    removeFromWatchlist: removeFromWatchlist,
    isInWatchlist: isInWatchlist,
  };
});
