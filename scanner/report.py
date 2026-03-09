import os


def get_badge(status):
    badges = {
        "PASS":    ('<span class="badge pass">PASS</span>', "#27ae60"),
        "FAIL":    ('<span class="badge fail">FAIL</span>', "#e74c3c"),
        "WARNING": ('<span class="badge warning">WARNING</span>', "#f39c12"),
        "ERROR":   ('<span class="badge error">ERROR</span>', "#8e44ad"),
    }
    return badges.get(status, (status, "#999"))


def get_severity_color(severity):
    return {
        "critical": "#e74c3c",
        "high":     "#e67e22",
        "medium":   "#f1c40f",
        "low":      "#3498db",
    }.get(severity, "#95a5a6")


def generate_html(data, config):
    summary  = data['summary']
    results  = data['results']
    scanner  = data['scanner']
    scan_time = data['scan_time']
    score    = summary['score']

    if score >= 80:
        risk_label, risk_color = "LOW RISK", "#27ae60"
    elif score >= 60:
        risk_label, risk_color = "MEDIUM RISK", "#f39c12"
    else:
        risk_label, risk_color = "HIGH RISK", "#e74c3c"

    rows = ""
    for r in results:
        badge, _ = get_badge(r['status'])
        sev      = r.get('severity', 'low')
        sev_col  = get_severity_color(sev)
        detail   = r.get('detail', '')
        fix      = r.get('fix', '')
        fix_html = f'<div class="fix">✦ Fix: <code>{fix}</code></div>' if fix else ''
        rows += f"""
        <tr>
          <td><code>{r.get('id','N/A')}</code></td>
          <td>{r['name']}</td>
          <td>{badge}</td>
          <td><span class="sev" style="color:{sev_col};font-weight:600">{sev.upper()}</span></td>
          <td>{detail}{fix_html}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Linux Security Compliance Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9}}
  header{{background:linear-gradient(135deg,#161b22,#21262d);padding:40px;border-bottom:3px solid #cc0000}}
  header h1{{font-size:2rem;color:#fff;letter-spacing:2px}}
  header p{{color:#8b949e;margin-top:6px;font-size:.9rem}}
  .meta{{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}}
  .meta span{{background:#21262d;padding:6px 14px;border-radius:20px;font-size:.8rem;color:#8b949e}}
  .scorecard{{display:flex;gap:20px;padding:30px 40px;flex-wrap:wrap;background:#161b22;border-bottom:1px solid #30363d}}
  .card{{background:#21262d;border-radius:12px;padding:24px 32px;text-align:center;flex:1;min-width:140px;border:1px solid #30363d}}
  .card .num{{font-size:2.4rem;font-weight:700;line-height:1}}
  .card .lbl{{font-size:.8rem;color:#8b949e;margin-top:6px;text-transform:uppercase;letter-spacing:1px}}
  .progress-wrap{{padding:20px 40px;background:#161b22}}
  .progress-bar{{height:14px;background:#30363d;border-radius:8px;overflow:hidden}}
  .progress-fill{{height:100%;border-radius:8px;background:linear-gradient(90deg,#cc0000,#ff6b6b);transition:width .6s ease}}
  .progress-label{{display:flex;justify-content:space-between;margin-top:6px;font-size:.8rem;color:#8b949e}}
  .container{{padding:30px 40px}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:12px;overflow:hidden;border:1px solid #30363d}}
  th{{background:#21262d;padding:14px 16px;text-align:left;font-size:.8rem;text-transform:uppercase;letter-spacing:1px;color:#8b949e;border-bottom:1px solid #30363d}}
  td{{padding:14px 16px;border-bottom:1px solid #21262d;font-size:.88rem;vertical-align:top}}
  tr:hover td{{background:#1c2128}}
  tr:last-child td{{border-bottom:none}}
  .badge{{padding:3px 10px;border-radius:12px;font-size:.75rem;font-weight:700;letter-spacing:.5px}}
  .pass{{background:#0d4429;color:#3fb950}}
  .fail{{background:#3d0b0b;color:#f85149}}
  .warning{{background:#3d2b00;color:#e3b341}}
  .error{{background:#2d1b4e;color:#bc8cff}}
  .fix{{margin-top:6px;font-size:.8rem;color:#8b949e}}
  code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:.8rem;color:#79c0ff}}
  footer{{text-align:center;padding:24px;color:#484f58;font-size:.8rem;border-top:1px solid #21262d}}
</style>
</head>
<body>
<header>
  <h1>🔐 Linux Security Compliance Report</h1>
  <p>{scanner['name']} v{scanner['version']} — Built by {scanner['author']}</p>
  <div class="meta">
    <span>📅 {scan_time}</span>
    <span>📋 CIS Benchmark Controls</span>
    <span style="color:{risk_color};font-weight:700">⚠ {risk_label}</span>
  </div>
</header>

<div class="scorecard">
  <div class="card"><div class="num" style="color:{risk_color}">{score}%</div><div class="lbl">Compliance Score</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{summary['passed']}</div><div class="lbl">Passed</div></div>
  <div class="card"><div class="num" style="color:#f85149">{summary['failed']}</div><div class="lbl">Failed</div></div>
  <div class="card"><div class="num" style="color:#e3b341">{summary['warnings']}</div><div class="lbl">Warnings</div></div>
  <div class="card"><div class="num" style="color:#8b949e">{summary['total']}</div><div class="lbl">Total Checks</div></div>
</div>

<div class="progress-wrap">
  <div class="progress-bar"><div class="progress-fill" style="width:{score}%"></div></div>
  <div class="progress-label"><span>0%</span><span>Compliance: {score}%</span><span>100%</span></div>
</div>

<div class="container">
  <table>
    <thead>
      <tr>
        <th>CIS ID</th><th>Check Name</th><th>Status</th><th>Severity</th><th>Details & Fix</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<footer>Generated by {scanner['name']} — Mapped to CIS Benchmark Controls — Red Hat Inspired</footer>
</body>
</html>"""

    out_dir   = os.path.join(os.path.dirname(__file__), '..', config['report']['output_dir'])
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, config['report']['html_file'])
    with open(html_path, 'w') as f:
        f.write(html)
    print(f"  HTML report saved: {html_path}")

