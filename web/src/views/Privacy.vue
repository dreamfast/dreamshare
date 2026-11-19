<script setup lang="ts">
import { computed } from 'vue'
import { renderBody } from '../lib/markdown'

const content = `## The short version

Your files are encrypted in your browser before they are sent. We store
encrypted blobs we cannot read. The link is the key, and we never see it.

## What we hold about you

For each share, while it exists:

- IP address, for abuse control and quotas
- Country, from Cloudflare, for monitoring
- Browser and OS, for support and bot detection
- File sizes and counts, for capacity
- Encrypted content, which nobody can read, including us
- If you ask for a download notification, the email address you typed,
  so we can send that one mail. It is not encrypted at rest, it is
  deleted the moment the mail is sent or the share ends, and it is the
  only thing we can read

## When it goes away

Every case deletes the files and all records within 24 hours of the
share's end, whether the share wiped itself on confirmed download,
reached its scheduled expiry, or was revoked.

## The link is the key

The decryption key lives in the part of the URL after the # symbol.
Browsers never send that to a server. We cannot read your files, recover
a lost link, or reset a key.

## What we deliberately do not have

- No accounts, no passwords on the public side
- No analytics, no third-party trackers, no advertising
- No server-side scanning, no content inspection
- No key escrow, no master key, no back door

## Contact

Privacy questions and data requests go through the main DreamFast
Solutions website. We respond within 30 days.
`

// static authored copy through the same sanitised renderer the share body
// uses, one pipeline for every markdown in the app
const legalHtml = computed(() => renderBody(content))
</script>

<template>
  <section class="legal">
    <div class="card page">
      <h1>Privacy, plainly</h1>
      <div class="content markdown" v-html="legalHtml" />
    </div>
  </section>
</template>

<style scoped>
.legal {
  max-width: 42rem;
  margin: 2rem auto;
  padding: 0 1rem;
}

.page {
  view-transition-name: page-card;
  padding: 1.75rem 2rem;
}

h1 {
  font-size: 26px;
  margin: 0 0 1.25rem;
}

.content {
  font-size: 14px;
  line-height: 24px;
  color: var(--on-surface-variant);
}

.content :deep(h2) {
  font-size: 18px;
  color: var(--on-surface);
  margin: 1.5rem 0 0.5rem;
}

.content :deep(ul) {
  padding-left: 1.25rem;
  margin: 0.5rem 0;
}

.content :deep(li) {
  margin: 0.35rem 0;
}

.content :deep(p) {
  margin: 0.6rem 0;
}
</style>
