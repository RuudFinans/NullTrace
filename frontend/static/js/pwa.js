(function () {
  const root = document.documentElement;
  const standalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
  const ios = /iphone|ipad|ipod/i.test(window.navigator.userAgent);

  root.classList.toggle("is-standalone", standalone);
  root.classList.toggle("is-ios", ios);

  function setViewportVars() {
    const viewport = window.visualViewport;
    const height = viewport ? viewport.height : window.innerHeight;
    const offsetTop = viewport ? viewport.offsetTop : 0;
    root.style.setProperty("--app-height", `${Math.round(height)}px`);
    root.style.setProperty("--viewport-offset-top", `${Math.round(offsetTop)}px`);
  }

  setViewportVars();
  window.addEventListener("resize", setViewportVars, { passive: true });
  window.addEventListener("orientationchange", setViewportVars, { passive: true });
  window.visualViewport?.addEventListener("resize", setViewportVars, { passive: true });
  window.visualViewport?.addEventListener("scroll", setViewportVars, { passive: true });

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
    });
  }
})();
