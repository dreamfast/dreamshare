// Markdown rendering for the share body. Raw html is off at the markdown
// layer and the output passes an allow-list sanitiser, because the sender
// controls the bytes and a hostile sender must not reach the recipient's
// origin. This is the single sanctioned html sink in the app.
import MarkdownIt from 'markdown-it'
import createDOMPurify from 'dompurify'

const md = new MarkdownIt({ html: false, linkify: false, typographer: false })

// in the browser the factory binds the real window, tests bind jsdom
const DOMPurify = createDOMPurify(globalThis.window ?? (globalThis as unknown as Window))

// link schemes a body may reference, javascript: and data: are refused
const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'mailto:'])

DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    const anchor = node as HTMLAnchorElement
    try {
      const url = new URL(anchor.getAttribute('href') ?? '', 'https://.invalid.local')
      if (!ALLOWED_SCHEMES.has(url.protocol)) {
        anchor.removeAttribute('href')
      }
    } catch {
      anchor.removeAttribute('href')
    }
    anchor.setAttribute('rel', 'noopener noreferrer')
    anchor.setAttribute('target', '_blank')
  }
})

export function renderBody(markdown: string): string {
  const raw = md.render(markdown ?? '')
  return DOMPurify.sanitize(raw, {
    ALLOWED_TAGS: [
      'p',
      'br',
      'strong',
      'em',
      'del',
      's',
      'code',
      'pre',
      'ul',
      'ol',
      'li',
      'a',
      'h1',
      'h2',
      'h3',
      'h4',
      'blockquote',
    ],
    ALLOWED_ATTR: ['href', 'title'],
  })
}
