// Right-click any selected text on any page → open Shield's scanning popup
// prefilled with that selection.
const MENU_ID = "shield-scan-selection";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Check selected text with Shield",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID || !info.selectionText) return;
  const query = new URLSearchParams({ text: info.selectionText.slice(0, 20000) });
  const popup = chrome.runtime.getURL("popup.html") + "?" + query.toString();
  if (tab?.id) {
    chrome.tabs.create({ url: popup });
  } else {
    chrome.tabs.query({ active: true, currentWindow: true }, ([]) => {
      chrome.tabs.create({ url: popup });
    });
  }
});