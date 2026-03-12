package main

import (
	"html/template"
	"net/http"
)

type pageData struct {
	LoggedIn   bool
	Username   string
	FirstName  string
	LastName   string
	SubjectID  string
	PrettyJSON string
	BotURL     string
}

var pageTpl = template.Must(template.New("index").Parse(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Simple Service Auth</title>
  <style>
    :root { --bg:#f7f8fb; --card:#ffffff; --text:#1e2430; --muted:#6a7485; --accent:#0ea5e9; --border:#d8deea; }
    body { margin:0; font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:radial-gradient(circle at top,#eef6ff,var(--bg)); color:var(--text); }
    .wrap { max-width:760px; margin:40px auto; padding:0 16px; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:18px; padding:24px; box-shadow:0 10px 25px rgba(30,36,48,.06); }
    h1 { margin:0 0 16px; font-size:36px; }
    p { color:var(--muted); }
    .row { display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; }
    a.btn { border:0; border-radius:12px; padding:10px 14px; cursor:pointer; text-decoration:none; font-weight:600; background:var(--accent); color:#fff; }
    pre { background:#0f172a; color:#dbeafe; padding:14px; border-radius:12px; overflow:auto; font-size:12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Simple Service With Auth</h1>
      {{if .LoggedIn}}
        <p>You are authenticated as <b>{{.SubjectID}}</b>.</p>
        <p>Name: <b>{{.FirstName}} {{.LastName}}</b> | Username: <b>{{.Username}}</b></p>
        <pre>{{.PrettyJSON}}</pre>
      {{else}}
        <p>Open the Telegram bot and use <b>/start</b> or <b>/login</b>. Bot will return a login link.</p>
        {{if .BotURL}}<div class="row"><a class="btn" href="{{.BotURL}}" target="_blank" rel="noreferrer">Open Bot</a></div>{{end}}
      {{end}}
    </div>
  </div>
</body>
</html>`))

func renderPage(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTpl.Execute(w, data)
}
