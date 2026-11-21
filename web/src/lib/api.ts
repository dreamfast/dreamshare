// The server API client. Same origin only, the CSRF pair comes from the
// bootstrap call and rides every mutation.

export interface BootstrapInfo {
  csrf_token: string
  turnstile: {
    enforced: boolean
    site_key: string
  }
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
    notify_email?: string
    passphrase_kdf?: { salt: string; iters: number }
  },
  turnstileToken?: string,
  signal?: AbortSignal,
): Promise<CreatedShare> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...csrfHeaders(csrf),
  }
  if (turnstileToken) headers['X-Turnstile-Token'] = turnstileToken
  const resp = await fetch('/api/shares', {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    ...(signal ? { signal } : {}),
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
  signal?: AbortSignal,
  onProgress?: (loaded: number, total: number) => void,
): Promise<{ ok: boolean; next_tokens: string[] }> {
  // xhr, not fetch: upload progress is only observable here. a part can
  // take long enough on a slow link that part level progress reads as
  // frozen, byte level keeps the bars honest
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `/api/sessions/${sessionID}/parts/${partNumber}`)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.setRequestHeader('X-CSRF-Token', csrf)
    xhr.setRequestHeader('X-Part-Token', partToken)
    xhr.setRequestHeader('X-Part-SHA256', sha256Hex)
    const onAbort = () => xhr.abort()
    signal?.addEventListener('abort', onAbort, { once: true })
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) onProgress?.(ev.loaded, ev.total)
    }
    xhr.onload = () => {
      let body: unknown
      try {
        body = JSON.parse(xhr.responseText)
      } catch {
        reject(new Error(`http_${xhr.status}`))
        return
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        const code =
          body && typeof body === 'object' && 'error' in body && typeof body.error === 'string'
            ? body.error
            : `http_${xhr.status}`
        reject(new Error(code))
        return
      }
      resolve(body as { ok: boolean; next_tokens: string[] })
    }
    xhr.onerror = () => reject(new Error('network'))
    xhr.onabort = () => reject(new Error('aborted'))
    xhr.send(data)
  })
}

export async function completeSession(
  csrf: string,
  sessionID: string,
  partToken: string,
  signal?: AbortSignal,
): Promise<void> {
  const resp = await fetch(`/api/sessions/${sessionID}/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf), 'X-Part-Token': partToken },
    body: '{}',
    ...(signal ? { signal } : {}),
  })
  await json(resp)
}

export async function finalizeShare(
  csrf: string,
  shareID: string,
  blobs: { title_ct: string; manifest_ct: string; check_ct: string; check_sha256: string },
  signal?: AbortSignal,
): Promise<void> {
  const resp = await fetch(`/api/shares/${shareID}/finalize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf) },
    body: JSON.stringify(blobs),
    ...(signal ? { signal } : {}),
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
  has_passphrase?: boolean
  kdf_salt?: string
  kdf_iters?: number
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

export async function ackFile(
  csrf: string,
  token: string,
  fileID: string | null,
  proof: string,
): Promise<void> {
  const resp = await fetch(`/api/shares/${token}/ack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders(csrf) },
    body: JSON.stringify({ file_id: fileID, verified: true, proof }),
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
