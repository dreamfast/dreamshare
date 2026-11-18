// The /mine records, this browser only. Clearing site data loses the list
// and the local revoke right, the link itself keeps working.

export interface MineRecord {
  shareID: string
  managerToken: string
  title: string
  createdAt: number
  expiryMode: string
  expiresAt: number
}

const KEY = 'dreamshare.mine.v1'

export function loadMine(): MineRecord[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return []
    const list = JSON.parse(raw) as MineRecord[]
    return Array.isArray(list) ? list : []
  } catch {
    return []
  }
}

export function saveMineRecord(rec: MineRecord): void {
  const list = loadMine()
  list.unshift(rec)
  localStorage.setItem(KEY, JSON.stringify(list.slice(0, 200)))
}

export function forgetMineRecord(shareID: string): void {
  const list = loadMine().filter((r) => r.shareID !== shareID)
  localStorage.setItem(KEY, JSON.stringify(list))
}
