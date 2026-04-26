import json 
from datetime import datetime 
import os 
import pathlib 

class ReportGenerator :
    """
    build structured Security Report JSON/HTML payloads based on the 
    amalgamated analysis state of the active Security Engines.
    """

    @staticmethod 
    def generate_json_report(data :dict )->str :
        """Returns JSON serialized report."""
        output ={
        "title":"Cybersecurity Companion Website Report",
        "timestamp":datetime.now().isoformat(),
        "target":data.get("url","Unknown"),
        "domain":data.get("domain","Unknown"),
        "risk_score":data.get("score",0 ),
        "risk_level":data.get("status","UNKNOWN"),
        "summary":{
        "https_status":data.get("https_status","Unknown"),
        "total_links":data.get("total_links",0 ),
        "total_scripts":data.get("total_scripts",0 ),
        "hidden_iframes":data.get("hidden_iframes",0 ),
        "password_forms":data.get("password_forms",0 ),
        "external_forms":data.get("external_forms",False ),
        "executables_linked":data.get("executables_linked",0 ),
        "crypto_wallets":data.get("crypto_wallets",False ),
        "typosquatting_risk":data.get("typosquatting_risk",False )
        },
        "privacy":{
        "risk_level":data.get("privacy_level","LOW"),
        "trackers":data.get("trackers",[])
        },
        "findings":data.get("flags",[])
        }
        return json.dumps(output, indent =4 )

    @staticmethod 
    def generate_html_report(data :dict )->str :
        """build an elegant static HTML payload for PDF/HTML export consumption."""
        flags_html ="".join([f"<li>{flag}</li>"for flag in data.get("flags",[])])
        trackers_html =", ".join(data.get("trackers",[]))or "None detected"

        status =data.get("status","UNKNOWN")
        bd_col ="#27ae60"if status =="SAFE"else "#f39c12"if status =="SUSPICIOUS"else "#c0392b"

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Report: {data.get("domain", "Unknown")}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            color: #333;
            max-width: 900px;
            margin: auto;
            padding: 40px;
            background: #fdfdfd;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid {bd_col};
            padding-bottom: 10px;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 30px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #ddd;
            box-shadow: 0 2px 4px rgba(0,0,0,0.02);
        }}
        .card h2 {{
            margin-top: 0;
            font-size: 1.2rem;
            color: #7f8c8d;
        }}
        .score {{
            font-size: 2.5rem;
            font-weight: bold;
            color: {bd_col};
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }}
        .threat-list {{
            background: #fff;
            border-left: 4px solid {bd_col};
            padding: 15px 20px;
        }}
        ul {{ padding-left: 20px; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p><strong>Target URL:</strong> <a href="{data.get('url', '#')}">{data.get('url', 'N/A')}</a></p>
    
    <div class="metric-grid">
        <div class="card" style="text-align: center;">
            <h2>Risk Score</h2>
            <div class="score">{data.get('score', 0)}/100</div>
            <p><strong>Level: {status}</strong></p>
        </div>
        <div class="card">
            <h2>Page Heuristics</h2>
            <table>
                <tr><td>HTTPS Secured</td><td>{'Yes' if data.get('https_status', False) else 'No'}</td></tr>
                <tr><td>Ext. Scripts</td><td>{data.get('total_scripts', 0)}</td></tr>
                <tr><td>Iframes</td><td>{data.get('hidden_iframes', 0)}</td></tr>
                <tr><td>Password Fields</td><td>{data.get('password_forms', 0)}</td></tr>
                <tr><td>Executables</td><td>{data.get('executables_linked', 0)}</td></tr>
            </table>
        </div>
    </div>
    
    <div class="threat-list">
        <h2>Detected Anomalies & Threats</h2>
        <ul>
            {flags_html if flags_html else "<li>No specific threats flagged.</li>"}
        </ul>
    </div>
    
    <div class="card" style="margin-top: 20px;">
        <h2>Privacy & Trackers</h2>
        <p><strong>Tracking Level:</strong> {data.get('privacy_level', 'LOW')}</p>
        <p><strong>Known Trackers Found:</strong> {trackers_html}</p>
    </div>
    
    <br><hr>
    <p style="text-align: center; color: #95a5a6; font-size: 0.9em;">Produced by GSD Cybersecurity Companion Analysis Engine.</p>
</body>
</html>
"""
