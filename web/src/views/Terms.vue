<script setup lang="ts">
import { computed } from 'vue'
import { renderBody } from '../lib/markdown'

const content = `**DreamFast Solutions Secure Share**

## What this service does

It moves files and text between two people with encryption that happens in
your browser before anything leaves your device. The server stores
ciphertext it cannot read.

## What we cannot do

- **Recover a lost link.** The encryption key is in the link's fragment.
It never reaches our server. If you lose the link, the files are gone and
nobody can get them back, including us.
- **Scan files for viruses.** We cannot read the contents.
- **Read your files under any circumstances.**

## What we store, and for how long

Your IP address, browser user agent, file sizes, timing and counts, for
abuse control and capacity planning. Records die with the share, within
24 hours of its end. Daily backups are kept 7 days.

## Notification emails

If you provide an email address for download notifications, it is encrypted
along with the files. The notification contains no link and no key.

## Your rights

Under Australian Privacy Principles and the GDPR, you can request a copy
of the personal data we hold and ask for its deletion. Contact us through
the main DreamFast Solutions website.

## Acceptable use

Do not use this service to move content that is illegal in Australia.
We cannot inspect content, but we can revoke a share and block an IP
address when we receive a credible report.

## No warranty

The service is provided as is. We are not liable for data loss caused by
a lost link, a browser bug, or a compromise of your device.
`

// static authored copy through the same sanitised renderer the share body
// uses, one pipeline for every markdown in the app
const legalHtml = computed(() => renderBody(content))
</script>

<template>
  <section class="legal">
    <div class="card page">
      <h1>Terms</h1>
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

.content :deep(strong) {
  color: var(--on-surface);
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
