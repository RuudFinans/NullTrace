(function () {
  const root = document.documentElement;
  const standalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
  const ios = /iphone|ipad|ipod/i.test(window.navigator.userAgent);
  let appHeight = Math.round(window.innerHeight || 0);

  root.classList.toggle("is-standalone", standalone);
  root.classList.toggle("is-ios", ios);

  function setKeyboardState(on) {
    root.classList.toggle("keyboard-active", !!on);
  }

  function setViewportVars() {
    const viewport = window.visualViewport;
    const visibleHeight = viewport ? viewport.height : window.innerHeight;
    const offsetTop = viewport ? viewport.offsetTop : 0;
    appHeight = Math.max(appHeight, Math.round(window.innerHeight || visibleHeight));
    const keyboardHeight = Math.max(0, appHeight - Math.round(visibleHeight + offsetTop));
    root.style.setProperty("--app-height", `${appHeight}px`);
    root.style.setProperty("--keyboard-height", `${keyboardHeight}px`);
    root.style.setProperty("--viewport-offset-top", `${Math.round(offsetTop)}px`);
  }

  setViewportVars();
  window.addEventListener("resize", setViewportVars, { passive: true });
  window.addEventListener("orientationchange", setViewportVars, { passive: true });
  window.visualViewport?.addEventListener("resize", setViewportVars, { passive: true });
  window.visualViewport?.addEventListener("scroll", setViewportVars, { passive: true });
  document.addEventListener("focusin", event => {
    if (event.target?.matches?.("#input")) {
      setKeyboardState(true);
      window.setTimeout(() => {
        setViewportVars();
      }, 80);
    }
  });
  document.addEventListener("focusout", () => {
    window.setTimeout(() => setKeyboardState(false), 80);
  });

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/sw.js", { scope: "/" }).then(registration => {
        registration.update().catch(() => {});
        registration.addEventListener("updatefound", () => {
          const worker = registration.installing;
          if (!worker) return;
          worker.addEventListener("statechange", () => {
            if (worker.state === "activated" && navigator.serviceWorker.controller) {
              window.location.reload();
            }
          });
        });
      }).catch(() => {});
    });
  }
})();
