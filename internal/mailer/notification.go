package mailer

import "fmt"

// DownloadNotification renders the download mail in both bodies. Email
// clients strip stylesheets and sandbox webfonts, so the html carries the
// brand palette inline in a table layout and the text part says the same
// thing without any styling.
func DownloadNotification(shareID string) (subject, text, html string) {
	subject = "Your share was downloaded"
	short := shareID
	if len(short) > 8 {
		short = short[:8]
	}
	text = fmt.Sprintf(
		"Your DreamShare %s was downloaded.\n\n"+
			"The link no longer works if it was set to wipe on download.\n\n"+
			"DreamShare by DreamFast Solutions",
		short,
	)
	html = fmt.Sprintf(emailTemplate, short)
	return subject, text, html
}

// emailTemplate spells css attributes the way mail clients require, the
// misspell pass would rename them to australian english and break the mail
//
//nolint:misspell
const emailTemplate = `<!doctype html>
<html>
<body style="margin:0;padding:0;background:#f8f9ff;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f8f9ff;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:420px;background:#ffffff;border-radius:14px;border:1px solid rgba(83,93,107,0.15);overflow:hidden;">
<tr><td style="padding:28px 32px 8px 32px;">
<div style="font-size:20px;line-height:28px;color:#344761;font-weight:400;">DreamShare</div>
<div style="width:44px;height:3px;background:#5c99ee;border-radius:2px;margin-top:6px;"></div>
</td></tr>
<tr><td style="padding:20px 32px 4px 32px;">
<div style="font-size:22px;line-height:30px;color:#344761;font-weight:400;">Your share was downloaded</div>
</td></tr>
<tr><td style="padding:8px 32px 28px 32px;">
<p style="margin:0 0 16px 0;font-size:15px;line-height:24px;color:#535d6b;">
Someone opened the share you sent. If it was set to wipe on download,
the link no longer works.
</p>
<p style="margin:0 0 24px 0;font-size:15px;line-height:24px;color:#535d6b;">
Share reference
</p>
<div style="background:#eef4ff;border-radius:8px;padding:10px 14px;font-size:14px;line-height:20px;color:#344761;font-family:monospace;">%s</div>
</td></tr>
<tr><td style="padding:16px 32px 24px 32px;border-top:1px solid rgba(83,93,107,0.12);">
<p style="margin:0;font-size:12px;line-height:18px;color:#535d6b;">
DreamShare by DreamFast Solutions. This mail contains no link and no key.
</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`
