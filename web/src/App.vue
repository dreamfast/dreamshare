<script setup lang="ts">
import { onMounted, ref } from 'vue'

const cryptoWorks = ref(true)

onMounted(() => {
  // crypto.subtle is undefined outside a secure context, say it plainly
  cryptoWorks.value = typeof globalThis.crypto?.subtle !== 'undefined'
})
</script>

<template>
  <div class="shell">
    <!-- ambient glow, the tinted canvas the cards float on -->
    <div class="glow glow-a" aria-hidden="true"></div>
    <div class="glow glow-b" aria-hidden="true"></div>

    <header class="topbar">
      <RouterLink to="/" class="brand">
        <img src="/img/logo.png" alt="" class="logo" />
        <span class="brand-name">DreamShare</span>
      </RouterLink>
      <nav class="topnav">
        <RouterLink to="/mine" class="navlink">My shares</RouterLink>
      </nav>
    </header>

    <main class="main">
      <p v-if="!cryptoWorks" class="nosecure" role="alert">
        This page encrypts in your browser and needs a secure context. Open it via localhost or https, not a
        plain http address.
      </p>
      <RouterView v-else />
    </main>

    <footer class="footer">
      <p>
        <RouterLink to="/">DreamShare</RouterLink> by
        <a href="https://dreamfast.solutions/" target="_blank" rel="noopener noreferrer"
          >DreamFast Solutions</a
        >
      </p>
      <p class="links">
        <RouterLink to="/terms">Terms</RouterLink> ·
        <RouterLink to="/privacy">Privacy</RouterLink>
      </p>
    </footer>
  </div>
</template>

<style>
/* brand fonts, same files the main site serves, no third-party request */
@font-face {
  font-family: 'Questrial';
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url(/fonts/questrial-latin.woff2) format('woff2');
}

@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 100 900;
  font-stretch: 100%;
  font-display: swap;
  src: url(/fonts/roboto-latin.woff2) format('woff2');
}

:root {
  /* canvas and cards, from the designer system */
  --surface: #f8f9ff;
  --card: #ffffff;
  --surface-low: #eef4ff;
  --surface-mid: #e5eeff;
  --surface-high: #dfe9fa;
  --surface-highest: #d9e3f4;
  /* ink */
  --on-surface: #121c28;
  --on-surface-variant: #424751;
  --secondary: #4d5f7b;
  /* brand */
  --accent: #5c99ee;
  --accent-deep: #0a5eb0;
  --on-accent: #ffffff;
  /* lines and states */
  --outline-variant: #c2c6d3;
  --outline-soft: rgba(83, 93, 107, 0.15);
  --error: #ba1a1a;
  --error-soft: #ffdad6;
  --warn-soft: #fff3e8;
  --warn-bar: #f0a05a;
  --good: #1e7a46;
  --good-soft: #e3f5ea;
  --mono: ui-monospace, 'SF Mono', 'Cascadia Mono', Menlo, Consolas, monospace;
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

html {
  scroll-behavior: smooth;
}

body {
  margin: 0;
  min-height: 100vh;
  font-family:
    'Roboto',
    system-ui,
    -apple-system,
    'Segoe UI',
    sans-serif;
  font-size: 14px;
  line-height: 22px;
  color: var(--on-surface);
  background-color: var(--surface);
  -webkit-font-smoothing: antialiased;
}

h1,
h2,
h3 {
  font-family: 'Questrial', sans-serif;
  font-weight: 400;
  color: var(--on-surface);
  margin: 0 0 0.5rem;
}

a {
  color: var(--accent-deep);
  text-decoration: none;
  transition: color 0.2s;
}

a:hover {
  color: var(--accent);
}

button {
  font-family: inherit;
}

.shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  position: relative;
}

/* the ambient light the mobile design carries, kept subtle */
.glow {
  position: fixed;
  border-radius: 50%;
  pointer-events: none;
  z-index: 0;
}

.glow-a {
  width: 36rem;
  height: 36rem;
  top: -6rem;
  right: -10rem;
  background: radial-gradient(circle, rgba(92, 153, 238, 0.14) 0%, transparent 70%);
}

.glow-b {
  width: 24rem;
  height: 24rem;
  bottom: -8rem;
  left: -6rem;
  background: radial-gradient(circle, rgba(229, 238, 255, 0.8) 0%, transparent 70%);
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 50;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 4rem;
  padding: 0 1.5rem;
  background: rgba(248, 249, 255, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--outline-soft);
}

.brand {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}

.brand .logo {
  height: 2rem;
  width: auto;
  object-fit: contain;
}

.brand-name {
  font-family: 'Questrial', sans-serif;
  font-size: 20px;
  line-height: 28px;
  color: var(--on-surface);
  letter-spacing: -0.01em;
}

.navlink {
  font-size: 14px;
  color: var(--on-surface-variant);
  padding: 0.25rem 0.6rem;
  border-radius: 8px;
  transition:
    color 0.2s,
    background 0.2s;
}

.navlink:hover {
  color: var(--accent-deep);
  background: var(--surface-low);
}

.main {
  flex: 1;
  position: relative;
  z-index: 1;
}

.footer {
  position: relative;
  z-index: 1;
  text-align: center;
  padding: 1.25rem 1rem;
  border-top: 1px solid var(--outline-soft);
}

.footer p {
  margin: 0.2rem 0;
  font-size: 12px;
  color: var(--on-surface-variant);
}

.footer .links a {
  font-size: 12px;
}

.nosecure {
  max-width: 32rem;
  margin: 4rem auto;
  padding: 1rem 1.25rem;
  border-radius: 12px;
  background: var(--error-soft);
  color: var(--on-surface);
}

/* shared building blocks used across the views */
.card {
  background: var(--card);
  border: 1px solid var(--outline-soft);
  border-radius: 16px;
  box-shadow: 0 10px 30px rgba(52, 71, 97, 0.06);
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  background: var(--accent);
  color: var(--on-accent);
  border: 2px solid transparent;
  padding: 12px 32px;
  border-radius: 8px;
  font-weight: 500;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  cursor: pointer;
  transition: all 0.25s ease;
  box-shadow: 0 5px 20px rgba(92, 153, 238, 0.3);
}

.btn-primary:hover:not(:disabled) {
  background: transparent;
  color: var(--accent);
  border-color: var(--accent);
  box-shadow: 0 8px 24px rgba(92, 153, 238, 0.18);
}

.btn-primary:disabled {
  opacity: 0.35;
  cursor: not-allowed;
  box-shadow: none;
}

.btn-ghost {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  background: transparent;
  border: 1px solid var(--outline-soft);
  color: var(--on-surface-variant);
  padding: 11px 24px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-ghost:hover {
  border-color: var(--accent);
  color: var(--accent-deep);
  background: rgba(92, 153, 238, 0.04);
}

/* shared element morph between pages, the group carries the same spring
   curve as the composer circle so both feel like one motion system.
   reduced motion is honoured in the route guard, this is belt and braces */
::view-transition-group(page-card) {
  animation-duration: 420ms;
  animation-timing-function: cubic-bezier(0.34, 1.3, 0.4, 1);
}

::view-transition-old(page-card),
::view-transition-new(page-card) {
  animation-duration: 200ms;
  animation-timing-function: ease;
  overflow: clip;
}

@media (prefers-reduced-motion: reduce) {
  ::view-transition-group(*),
  ::view-transition-old(*),
  ::view-transition-new(*) {
    animation: none !important;
  }
}

.btn-danger {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  background: transparent;
  border: 1px solid transparent;
  color: var(--error);
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-danger:hover {
  background: var(--error);
  color: #fff;
}
</style>
