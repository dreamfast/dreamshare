// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { renderBody } from './markdown'

describe('renderBody', () => {
  it('renders the safe subset', () => {
    const html = renderBody('# Title\n\n**bold** and `code` [link](https://example.com)')
    expect(html).toContain('<h1>Title</h1>')
    expect(html).toContain('<strong>bold</strong>')
    expect(html).toContain('href="https://example.com"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it('raw html never reaches the dom as markup', () => {
    const html = renderBody('<script>alert(1)</script><img src=x onerror=alert(1)>')
    // markdown-it with html:false escapes it, dompurify is the second layer,
    // the property is that no unescaped tag reaches the dom, the visible
    // text can spell the payload without executing anything
    expect(html).not.toMatch(/<(script|img)\b/i)
  })

  it('refuses javascript: and data: links, keeps mailto', () => {
    const html = renderBody('[a](javascript:alert(1)) [b](data:text/html,x) [c](mailto:someone@example.com)')
    // no hostile href attribute may exist, markdown-it refuses the schemes
    // and dompurify would strip the attribute anyway
    expect(html).not.toContain('href="javascript:')
    expect(html).not.toContain('href="data:')
    expect(html).toContain('href="mailto:someone@example.com"')
  })

  it('drops disallowed tags but keeps their text', () => {
    const html = renderBody('<table><tr><td>cell</td></tr></table>')
    expect(html).not.toContain('<table')
    expect(html).toContain('cell')
  })

  it('empty body renders empty', () => {
    expect(renderBody('')).toBe('')
  })
})
