# HikariSystem Tsurugi/core/reporter.py
"""
PROFESSIONAL REPORT GENERATOR
Generates beautiful HTML reports for Bug Bounty submissions.
"""
import os
import json
import datetime
from pathlib import Path
from jinja2 import Template
from core.ui import console, log_info, log_success

# Severity mapping for vulnerabilities
SEVERITY_MAP = {
    "sqli": {"level": "Critical", "color": "#dc3545", "score": 9.8},
    "sqli_blind": {"level": "Critical", "color": "#dc3545", "score": 9.5},
    "xss": {"level": "High", "color": "#fd7e14", "score": 7.5},
    "ssti": {"level": "Critical", "color": "#dc3545", "score": 9.8},
    "lfi": {"level": "High", "color": "#fd7e14", "score": 8.0},
    "ssrf": {"level": "High", "color": "#fd7e14", "score": 8.5},
    "redirect": {"level": "Medium", "color": "#ffc107", "score": 5.0},
    "cors": {"level": "Medium", "color": "#ffc107", "score": 5.5},
    "jwt": {"level": "High", "color": "#fd7e14", "score": 7.0},
    "secrets": {"level": "High", "color": "#fd7e14", "score": 8.0},
    "fuzzer": {"level": "Info", "color": "#17a2b8", "score": 3.0},
    "headers": {"level": "Low", "color": "#28a745", "score": 2.0},
}

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TSURUGI Security Report - {{ date }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(90deg, var(--critical), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        .header .subtitle { color: var(--text-secondary); font-size: 1.1em; }
        .header .date { color: var(--text-secondary); margin-top: 15px; font-size: 0.9em; }
        
        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { color: var(--text-secondary); font-size: 0.9em; }
        .stat-card.critical .number { color: var(--critical); }
        .stat-card.high .number { color: var(--high); }
        .stat-card.medium .number { color: var(--medium); }
        .stat-card.low .number { color: var(--low); }
        
        /* Findings */
        .findings { margin-top: 30px; }
        .findings h2 { margin-bottom: 20px; color: var(--accent); }
        
        .finding-card {
            background: var(--bg-secondary);
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid #30363d;
            cursor: pointer;
        }
        
        .finding-header:hover { background: var(--bg-tertiary); }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .finding-title { font-weight: 600; flex-grow: 1; margin-left: 15px; }
        .finding-url { color: var(--text-secondary); font-size: 0.85em; margin-left: 15px; }
        
        .finding-body { padding: 20px; display: block; }
        
        .payload-box {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            color: #7ee787;
            margin-top: 10px;
        }
        
        .detail-row { margin-bottom: 10px; }
        .detail-label { color: var(--text-secondary); font-size: 0.85em; }
        .detail-value { color: var(--text-primary); }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85em;
            border-top: 1px solid #30363d;
            margin-top: 40px;
        }
        
        .footer a { color: var(--accent); text-decoration: none; }
        
        /* Print styles */
        @media print {
            body { background: white; color: black; }
            .finding-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TSURUGI SECURITY REPORT</h1>
            <p class="subtitle">Automated Vulnerability Assessment</p>
            <p class="date">Generated: {{ date }}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">{{ total }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{{ critical }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{{ high }}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{{ medium }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{{ low + info }}</div>
                <div class="label">Low/Info</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>Vulnerability Details</h2>
            
            {% if not findings %}
            <div class="finding-card">
                <div class="finding-body">
                    <p>No vulnerabilities found in the loot directory.</p>
                    <p style="color: var(--text-secondary); margin-top: 10px;">
                        Run scans first: <code>python tsurugi.py attack "url"</code>
                    </p>
                </div>
            </div>
            {% endif %}
            
            {% for finding in findings %}
            <div class="finding-card">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {{ finding.color }};">
                        {{ finding.severity }}
                    </span>
                    <span class="finding-title">{{ finding.module | upper }}</span>
                    <span class="finding-url">{{ finding.target }}</span>
                </div>
                <div class="finding-body">
                    <div class="detail-row">
                        <span class="detail-label">CVSS Estimate:</span>
                        <span class="detail-value">{{ finding.cvss }}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Timestamp:</span>
                        <span class="detail-value">{{ finding.timestamp }}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Details:</span>
                        <div class="payload-box">{{ finding.details }}</div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>TSURUGI Framework v3.1</strong></p>
            <p>Part of <a href="#">HikariSystem</a> Security Suite</p>
        </div>
    </div>
</body>
</html>
"""

def generate_report(output_dir: str = "reports") -> str:
    """
    Generate professional HTML report from loot directory.
    
    Returns:
        Path to generated report file
    """
    loot_dir = Path("loot")
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    if not loot_dir.exists():
        console.print("[yellow]No loot directory found.[/yellow]")
        return None
    
    # Collect findings
    findings = []
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for json_file in loot_dir.glob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            module = data.get("module", "unknown")
            severity_info = SEVERITY_MAP.get(module, {"level": "Info", "color": "#17a2b8", "score": 1.0})
            
            finding = {
                "module": module,
                "target": data.get("target", "Unknown"),
                "timestamp": data.get("timestamp", "Unknown"),
                "severity": severity_info["level"],
                "color": severity_info["color"],
                "cvss": severity_info["score"],
                "details": json.dumps(data.get("details", {}), indent=2, ensure_ascii=False)
            }
            findings.append(finding)
            
            # Count by severity
            level = severity_info["level"].lower()
            if level in stats:
                stats[level] += 1
            else:
                stats["info"] += 1
                
        except Exception as e:
            console.print(f"[dim]Skipped {json_file.name}: {e}[/dim]")
    
    # Sort by severity (critical first)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    
    # Render template
    template = Template(TEMPLATE)
    html = template.render(
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings,
        total=len(findings),
        **stats
    )
    
    # Save report
    report_name = f"tsurugi_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = output_path / report_name
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    log_success(f"Report generated: {report_path}")
    console.print(f"[dim]Open in browser to view. Print to PDF with Ctrl+P.[/dim]")
    
    return str(report_path)
