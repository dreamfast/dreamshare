// The server API client. Same origin only, the CSRF pair comes from the
// bootstrap call and rides every mutation.

export interface BootstrapInfo {
  csrf_token: string
  limits: {
    max_share_bytes: number
    max_files_per_share: number
    chunk_min_bytes: number
    chunk_max_bytes: number
    frame_size: number
    expiry_modes: string[]
    expiry_days: number[]
  }
}

export interface UploadSession {
  session_id: string
  file_id: string
  expected_parts: number
  part_size: number
  multipart: boolean
  first_tokens: string[]
}

export interface CreatedShare {
  share_id: string
  manager_token: string
  upload_sessions: UploadSession[]
}

async function json<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    let code = `http_${resp.status}`
    try {
      const body = await resp.json()
      if (body?.error) code = body.error
    } catch {
      // keep the http code
    }
    throw new Error(code)
  }
  return resp.json() as Promise<T>
}

export async function bootstrap(): Promise<BootstrapInfo> {
  const resp = await fetch('/api/bootstrap')
  const info = await json<BootstrapInfo>(resp)
  return info
}

function csrfHeaders(token: string): Record<string, string> {
  return { 'X-CSRF-Token': token }
}

export function csrfCookie(): string {
  const m = document.cookie.match(/(?:^|;\s*)ds_csrf=([^;]+)/)
  return m?.[1] ?? ''
}

export async function createShare(
  csrf: string,
  body: {
    files: Array<{ size: number; frame_count: number; frame_size: number; part_size: number }>
    expiry_mode: string
    expiry_days: number
    notify_wanted: boolean
    turnstile_token?: string
  },
): Promise<CreatedShare> {
  const resp = await fetch('/api/shares', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf) },
    body: JSON.stringify(body),
  })
  return json<CreatedShare>(resp)
}

export async function putPart(
  csrf: string,
  sessionID: string,
  partNumber: number,
  data: ArrayBuffer,
  sha256Hex: string,
  partToken: string,
): Promise<{ ok: boolean; next_tokens: string[] }> {
  const resp = await fetch(`/api/sessions/${sessionID}/parts/${partNumber}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      ...csrfHeaders(csrf),
      'X-Part-Token': partToken,
      'X-Part-SHA256': sha256Hex,
    },
    body: data,
  })
  return json(resp)
}

export async function completeSession(csrf: string, sessionID: string, partToken: string): Promise<void> {
  const resp = await fetch(`/api/sessions/${sessionID}/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf), 'X-Part-Token': partToken },
    body: '{}',
  })
  await json(resp)
}

export async function finalizeShare(
  csrf: string,
  shareID: string,
  blobs: { title_ct: string; manifest_ct: string; check_ct: string },
): Promise<void> {
  const resp = await fetch(`/api/shares/${shareID}/finalize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf) },
    body: JSON.stringify(blobs),
  })
  await json(resp)
}

export interface ShareMeta {
  share_id: string
  format_version: string
  status: string
  expiry_mode: string
  expires_at: number
  file_count: number
  total_bytes: number
}

export async function shareMeta(token: string): Promise<ShareMeta> {
  const resp = await fetch(`/api/shares/${token}`)
  return json(resp)
}

export async function fetchCheck(token: string): Promise<Uint8Array | null> {
  const resp = await fetch(`/api/shares/${token}/check`)
  if (!resp.ok) return null
  return new Uint8Array(await resp.arrayBuffer())
}

export async function downloadFile(token: string, fileID: string): Promise<Uint8Array> {
  const resp = await fetch(`/dl/${token}/${fileID}`)
  if (!resp.ok) throw new Error(await resp.text().catch(() => `http_${resp.status}`))
  return new Uint8Array(await resp.arrayBuffer())
}

export async function ackFile(csrf: string, token: string, fileID: string | null): Promise<void> {
  const resp = await fetch(`/api/shares/${token}/ack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf) },
    body: JSON.stringify({ file_id: fileID, verified: true }),
  })
  await json(resp)
}

export async function notifyDownloaded(csrf: string, token: string, to: string): Promise<void> {
  const resp = await fetch(`/api/shares/${token}/notify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf) },
    body: JSON.stringify({ to }),
  })
  await json(resp)
}

export async function revokeShare(shareID: string, managerToken: string): Promise<void> {
  const resp = await fetch(`/api/shares/${shareID}`, {
    method: 'DELETE',
    headers: { 'X-Manager-Token': managerToken },
  })
  if (!resp.ok && resp.status !== 404) throw new Error(`http_${resp.status}`)
}
