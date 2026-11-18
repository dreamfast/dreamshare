<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { revokeShare } from '../lib/api'
import { forgetMineRecord, loadMine, type MineRecord } from '../lib/mine'

const records = ref<MineRecord[]>([])
const revoking = ref('')

onMounted(() => {
  records.value = loadMine()
})

async function revoke(rec: MineRecord) {
  revoking.value = rec.shareID
  try {
    await revokeShare(rec.shareID, rec.managerToken)
  } catch {
    // 404 means already gone, the local record drops either way
  }
  forgetMineRecord(rec.shareID)
  records.value = loadMine()
  revoking.value = ''
}

const ago = (ts: number) => {
  const mins = Math.round((Date.now() - ts) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} minute${mins > 1 ? 's' : ''} ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs} hour${hrs > 1 ? 's' : ''} ago`
  const days = Math.round(hrs / 24)
  return `${days} day${days > 1 ? 's' : ''} ago`
}

const expiryText = (rec: MineRecord) =>
  rec.expiryMode === 'burn_on_ack'
    ? 'Wipes on first download'
    : `Expires ${new Date(rec.expiresAt).toLocaleDateString()}`
</script>

<template>
  <section class="mine">
    <div class="card page">
      <div class="head">
        <div>
          <h1>My shares</h1>
          <p class="head-sub">Shares created in this browser.</p>
        </div>
        <RouterLink to="/" class="btn-primary create">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.4"
            stroke-linecap="round"
            aria-hidden="true"
          >
            <path d="M12 5v14M5 12h14" />
          </svg>
          Create share
        </RouterLink>
      </div>

      <p class="notice">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path
            d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
          />
        </svg>
        This list lives in this browser only. Clearing site data loses it and the revoke rights with it.
      </p>

      <div v-if="!records.length" class="empty">
        <p>Nothing here yet.</p>
        <RouterLink to="/" class="btn-primary">Share something</RouterLink>
      </div>

      <ul v-else class="list">
        <li v-for="rec in records" :key="rec.shareID" class="row">
          <span class="row-icon" aria-hidden="true">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
              <polyline points="13 2 13 9 20 9" />
            </svg>
          </span>
          <span class="meta">
            <span class="title-row">
              <span class="title">{{ rec.title }}</span>
              <span class="pill" :class="{ burn: rec.expiryMode === 'burn_on_ack' }">{{
                expiryText(rec)
              }}</span>
            </span>
            <span class="meta-line">Created {{ ago(rec.createdAt) }}</span>
          </span>
          <button type="button" class="btn-danger" :disabled="revoking === rec.shareID" @click="revoke(rec)">
            {{ revoking === rec.shareID ? 'Revoking…' : 'Revoke' }}
          </button>
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.mine {
  max-width: 48rem;
  margin: 2rem auto;
  padding: 0 1rem;
}

.page {
  view-transition-name: page-card;
  padding: 1.75rem 2rem;
  position: relative;
  overflow: hidden;
}

/* corner glow like the design */
.page::before {
  content: '';
  position: absolute;
  top: -4rem;
  right: -4rem;
  width: 11rem;
  height: 11rem;
  border-radius: 50%;
  background: rgba(92, 153, 238, 0.1);
  filter: blur(2.5rem);
  pointer-events: none;
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1.25rem;
  position: relative;
}

h1 {
  font-size: 24px;
  margin: 0;
}

.head-sub {
  margin: 0.15rem 0 0;
  font-size: 13px;
  color: var(--on-surface-variant);
}

.create {
  padding: 10px 22px;
  flex-shrink: 0;
}

.create svg {
  width: 0.95rem;
  height: 0.95rem;
}

.notice {
  display: flex;
  gap: 0.6rem;
  align-items: flex-start;
  margin: 0 0 1.4rem;
  font-size: 13px;
  line-height: 20px;
  color: var(--on-surface-variant);
  background: var(--surface-low);
  border-radius: 10px;
  padding: 0.75rem 0.9rem;
  position: relative;
}

.notice svg {
  width: 1.05rem;
  height: 1.05rem;
  color: var(--accent);
  flex-shrink: 0;
  margin-top: 0.1rem;
}

.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  padding: 2.5rem 1rem;
  position: relative;
}

.empty p {
  margin: 0;
  color: var(--on-surface-variant);
}

.list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
  position: relative;
}

.row {
  display: flex;
  gap: 0.9rem;
  align-items: center;
  padding: 0.9rem 1rem;
  border-radius: 12px;
  border: 1px solid var(--outline-soft);
  background: var(--card);
  transition:
    background 0.2s,
    border-color 0.2s;
}

.row:hover {
  background: rgba(238, 244, 255, 0.4);
  border-color: rgba(92, 153, 238, 0.3);
}

.row-icon {
  display: flex;
  width: 2.5rem;
  height: 2.5rem;
  border-radius: 10px;
  background: rgba(92, 153, 238, 0.1);
  color: var(--accent-deep);
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.row-icon svg {
  width: 1.15rem;
  height: 1.15rem;
}

.meta {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.title-row {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
  min-width: 0;
}

.title {
  font-weight: 500;
  font-size: 14px;
  overflow-wrap: anywhere;
}

.pill {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.4px;
  text-transform: uppercase;
  border-radius: 9999px;
  padding: 2px 9px;
  background: var(--surface-highest);
  color: var(--on-surface-variant);
  white-space: nowrap;
}

.pill.burn {
  background: var(--warn-soft);
  color: #a84201;
}

.meta-line {
  font-size: 12px;
  color: var(--on-surface-variant);
}

@media (max-width: 640px) {
  .page {
    padding: 1.25rem;
  }

  .head {
    flex-direction: column;
    align-items: flex-start;
  }

  .row {
    flex-wrap: wrap;
  }

  .btn-danger {
    order: 3;
    width: 100%;
  }
}
</style>
