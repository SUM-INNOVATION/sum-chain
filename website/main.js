'use strict';

/* =============================================
   NAV
   ============================================= */
const nav = document.getElementById('nav');
window.addEventListener('scroll', () => {
  nav.classList.toggle('scrolled', window.scrollY > 40);
}, { passive: true });

/* =============================================
   MOBILE MENU
   ============================================= */
(function initMenu() {
  const btn = document.getElementById('menuBtn');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const open = document.body.classList.toggle('menu-open');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
})();

/* =============================================
   LIVE NETWORK DATA
   The hero readout is wired to mainnet RPC.
   Polls finality every 3s (one block interval);
   a pulse travels the hairline when a block lands.
   ============================================= */
(function initLive() {
  const elHeight = document.getElementById('liveHeight');
  if (!elHeight) return;

  const elFinal  = document.getElementById('liveFinal');
  const elEpoch  = document.getElementById('liveEpoch');
  const elVals   = document.getElementById('liveVals');
  const track    = document.getElementById('pulseTrack');

  const RPC = 'https://rpc.sumchain.io';
  const fmt = n => n.toLocaleString('en-US');

  async function rpc(method, params) {
    const res = await fetch(RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method, params: params || [], id: 1 }),
    });
    const json = await res.json();
    if (json.error) throw new Error(json.error.message);
    return json.result;
  }

  // Animate a numeric readout from its current value to the target
  function countTo(el, target) {
    const from  = Number(el.dataset.v || target);
    const delta = target - from;
    el.dataset.v = target;
    if (!delta) { el.textContent = fmt(target); return; }
    const t0 = performance.now();
    const DUR = 500;
    (function tick(now) {
      const p = Math.min((now - t0) / DUR, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(Math.round(from + delta * eased));
      if (p < 1) requestAnimationFrame(tick);
    })(t0);
  }

  function firePulse() {
    if (!track) return;
    track.classList.remove('go');
    void track.offsetWidth; // restart the animation
    track.classList.add('go');
  }

  let lastHeight = 0;
  let failures = 0;

  async function refresh(first) {
    try {
      const fin = await rpc('get_finality');
      failures = 0;
      if (fin.current_height !== lastHeight) {
        if (first) elHeight.dataset.v = Math.max(fin.current_height - 40, 0);
        lastHeight = fin.current_height;
        countTo(elHeight, fin.current_height);
        countTo(elFinal, fin.finalized_height);
        if (!first) firePulse();
      }
    } catch (e) {
      failures += 1;
      if (failures > 4) clearInterval(timer);
      if (first) {
        [elHeight, elFinal, elEpoch, elVals].forEach(el => { el.textContent = '···'; });
      }
    }
  }

  async function loadStatic() {
    try {
      const epoch = await rpc('epoch_getInfo');
      elEpoch.textContent = fmt(epoch.current_epoch);
    } catch (e) { /* keep placeholder */ }
    try {
      const vals = await rpc('get_validators');
      elVals.textContent = fmt(vals.validators.length);
    } catch (e) { /* keep placeholder */ }
  }

  refresh(true);
  loadStatic();
  const timer = setInterval(() => refresh(false), 3000);
})();

/* =============================================
   SCROLL REVEAL
   ============================================= */
const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.08, rootMargin: '0px 0px -24px 0px' });

document.querySelectorAll('.pillar, .stat, .spec-row').forEach((el, i) => {
  el.classList.add('reveal');
  el.style.transitionDelay = `${(i % 8) * 55}ms`;
  observer.observe(el);
});

/* =============================================
   SMOOTH SCROLL (offset for fixed nav)
   ============================================= */
document.querySelectorAll('a[href^="#"]').forEach(link => {
  link.addEventListener('click', e => {
    const id = link.getAttribute('href').slice(1);
    if (!id) return;
    const target = document.getElementById(id);
    if (!target) return;
    e.preventDefault();
    const offset = nav.getBoundingClientRect().height + 12;
    window.scrollTo({
      top: target.getBoundingClientRect().top + window.scrollY - offset,
      behavior: 'smooth',
    });
  });
});
