"""
Visualization Module - Interactive Dashboard Generator
Creates interactive HTML dashboards with charts, maps, and tables
"""

import json
import datetime
from typing import List, Dict, Any
from pathlib import Path


class DashboardGenerator:
    """Generate interactive HTML dashboards"""
    
    def __init__(self):
        self.template = self._get_template()
    
    def _get_template(self) -> str:
        """Get HTML template with all libraries"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valac Security Scan Dashboard</title>
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <!-- Leaflet for maps -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    
    <!-- DataTables for interactive tables -->
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 30px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #667eea;
        }
        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            font-size: 2.5em;
            margin-bottom: 5px;
        }
        .stat-card p {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .stat-card.critical { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .stat-card.high { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .stat-card.low { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }
        
        .section {
            margin-bottom: 40px;
        }
        .section-title {
            font-size: 1.8em;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .chart-container {
            position: relative;
            height: 400px;
            margin-bottom: 30px;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
        }
        .map-container {
            height: 500px;
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table thead {
            background: #667eea;
            color: white;
        }
        table th, table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        table tbody tr:hover {
            background: #f5f5f5;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .badge.critical { background: #f5576c; color: white; }
        .badge.high { background: #fa709a; color: white; }
        .badge.medium { background: #4facfe; color: white; }
        .badge.low { background: #43e97b; color: white; }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Valac Security Scan Dashboard</h1>
            <div class="subtitle">Scan Date: {scan_date}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>{total_targets}</h3>
                <p>Total Targets</p>
            </div>
            <div class="stat-card critical">
                <h3>{critical_count}</h3>
                <p>Critical Risk</p>
            </div>
            <div class="stat-card high">
                <h3>{high_count}</h3>
                <p>High Risk</p>
            </div>
            <div class="stat-card medium">
                <h3>{medium_count}</h3>
                <p>Medium Risk</p>
            </div>
            <div class="stat-card low">
                <h3>{low_count}</h3>
                <p>Low Risk</p>
            </div>
            <div class="stat-card">
                <h3>{total_vulns}</h3>
                <p>Vulnerabilities</p>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Risk Level Distribution</h2>
            <div class="chart-container">
                <canvas id="riskChart"></canvas>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Vulnerability Distribution</h2>
            <div class="chart-container">
                <canvas id="vulnChart"></canvas>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Top Ports</h2>
            <div class="chart-container">
                <canvas id="portChart"></canvas>
            </div>
        </div>
        
        {map_section}
        
        <div class="section">
            <h2 class="section-title">Scan Results</h2>
            <table id="resultsTable" class="display">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Risk Level</th>
                        <th>Severity</th>
                        <th>Ports</th>
                        <th>Vulnerabilities</th>
                        <th>Hostnames</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by Valac Security Scanner v1.0</p>
        </div>
    </div>
    
    <script>
        // Risk Level Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{critical_count}, {high_count}, {medium_count}, {low_count}],
                    backgroundColor: [
                        '#f5576c',
                        '#fa709a',
                        '#4facfe',
                        '#43e97b'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right'
                    }},
                    title: {{
                        display: true,
                        text: 'Risk Level Distribution'
                    }}
                }}
            }}
        }});
        
        // Vulnerability Chart
        const vulnCtx = document.getElementById('vulnChart').getContext('2d');
        new Chart(vulnCtx, {{
            type: 'bar',
            data: {{
                labels: {vuln_labels},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {vuln_data},
                    backgroundColor: '#667eea'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    title: {{
                        display: true,
                        text: 'Top 10 CVEs'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        
        // Ports Chart
        const portCtx = document.getElementById('portChart').getContext('2d');
        new Chart(portCtx, {{
            type: 'bar',
            data: {{
                labels: {port_labels},
                datasets: [{{
                    label: 'Open Ports',
                    data: {port_data},
                    backgroundColor: '#764ba2'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    title: {{
                        display: true,
                        text: 'Top 10 Open Ports'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        
        {map_script}
        
        // Initialize DataTable
        $(document).ready(function() {{
            $('#resultsTable').DataTable({{
                order: [[2, 'desc']],
                pageLength: 25,
                responsive: true,
                columnDefs: [
                    {{ targets: [1], orderable: true }},
                    {{ targets: [2], orderable: true }}
                ]
            }});
        }});
    </script>
</body>
</html>"""
    
    def generate(self, results: List[Dict], output_file: str):
        """Generate interactive dashboard from scan results"""
        if not results:
            return
        
        # Calculate statistics
        stats = self._calculate_stats(results)
        
        # Prepare data for charts
        vuln_data = self._get_vulnerability_data(results)
        port_data = self._get_port_data(results)
        
        # Generate map
        map_section, map_script = self._generate_map(results)
        
        # Generate table rows
        table_rows = self._generate_table_rows(results)
        
        # Format template
        html = self.template.format(
            scan_date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_targets=len(results),
            critical_count=stats['critical'],
            high_count=stats['high'],
            medium_count=stats['medium'],
            low_count=stats['low'],
            total_vulns=stats['total_vulns'],
            vuln_labels=json.dumps(vuln_data['labels']),
            vuln_data=json.dumps(vuln_data['data']),
            port_labels=json.dumps(port_data['labels']),
            port_data=json.dumps(port_data['data']),
            map_section=map_section,
            map_script=map_script,
            table_rows=table_rows
        )
        
        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _calculate_stats(self, results: List[Dict]) -> Dict:
        """Calculate statistics from results"""
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total_vulns': 0
        }
        
        for result in results:
            risk = result.get('risk_level', 'LOW').upper()
            if risk == 'CRITICAL':
                stats['critical'] += 1
            elif risk == 'HIGH':
                stats['high'] += 1
            elif risk == 'MEDIUM':
                stats['medium'] += 1
            else:
                stats['low'] += 1
            
            stats['total_vulns'] += len(result.get('vulns', []))
        
        return stats
    
    def _get_vulnerability_data(self, results: List[Dict]) -> Dict:
        """Get top vulnerabilities for chart"""
        vuln_count = {}
        
        for result in results:
            for vuln in result.get('vulns', []):
                vuln_count[vuln] = vuln_count.get(vuln, 0) + 1
        
        # Get top 10
        top_vulns = sorted(vuln_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'labels': [v[0] for v in top_vulns],
            'data': [v[1] for v in top_vulns]
        }
    
    def _get_port_data(self, results: List[Dict]) -> Dict:
        """Get top ports for chart"""
        port_count = {}
        
        for result in results:
            for port in result.get('ports', []):
                port_count[port] = port_count.get(port, 0) + 1
        
        # Get top 10
        top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'labels': [str(p[0]) for p in top_ports],
            'data': [p[1] for p in top_ports]
        }
    
    def _generate_map(self, results: List[Dict]) -> tuple:
        """Generate map section with markers"""
        # Filter results with geolocation
        geo_results = [r for r in results if r.get('geolocation') and r['geolocation'].get('lat')]
        
        if not geo_results:
            return ('', '')
        
        # Generate markers
        markers = []
        for result in geo_results:
            geo = result['geolocation']
            lat = geo.get('lat')
            lon = geo.get('lon')
            # Validate coordinates
            if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
                markers.append({
                    'lat': float(lat),
                    'lon': float(lon),
                    'ip': result.get('ip', ''),
                    'risk': result.get('risk_level', 'UNKNOWN'),
                    'vulns': len(result.get('vulns', []))
                })
        
        if not markers:
            return ('', '')
        
        # Generate map HTML
        map_html = f"""
        <div class="section">
            <h2 class="section-title">Geographic Distribution</h2>
            <div id="map" class="map-container"></div>
        </div>
        """
        
        # Generate map script
        markers_js = json.dumps(markers)
        # Calculate center from markers
        avg_lat = sum(m['lat'] for m in markers) / len(markers)
        avg_lon = sum(m['lon'] for m in markers) / len(markers)
        map_script = f"""
        // Initialize map
        const map = L.map('map').setView([{avg_lat}, {avg_lon}], 2);
        
        // Add tile layer
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '© OpenStreetMap contributors'
        }}).addTo(map);
        
        // Add markers
        const markers = {markers_js};
        const riskColors = {{
            'CRITICAL': '#f5576c',
            'HIGH': '#fa709a',
            'MEDIUM': '#4facfe',
            'LOW': '#43e97b'
        }};
        
        markers.forEach(marker => {{
            const color = riskColors[marker.risk] || '#667eea';
            const circle = L.circleMarker([marker.lat, marker.lon], {{
                radius: Math.max(5, Math.min(15, marker.vulns * 2)),
                fillColor: color,
                color: '#fff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.7
            }}).addTo(map);
            
            circle.bindPopup(`
                <b>IP:</b> ${{marker.ip}}<br>
                <b>Risk:</b> ${{marker.risk}}<br>
                <b>Vulnerabilities:</b> ${{marker.vulns}}
            `);
        }});
        
        // Fit bounds to show all markers
        if (markers.length > 1) {{
            const bounds = markers.map(m => [m.lat, m.lon]);
            map.fitBounds(bounds);
        }}
        """
        
        return (map_html, map_script)
    
    def _generate_table_rows(self, results: List[Dict]) -> str:
        """Generate HTML table rows"""
        rows = []
        
        for result in results:
            ip = result.get('ip', '')
            risk = result.get('risk_level', 'UNKNOWN')
            severity = f"{result.get('severity_score', 0):.1f}"
            ports = ', '.join(map(str, result.get('ports', [])[:5]))
            if len(result.get('ports', [])) > 5:
                ports += f" (+{len(result.get('ports', [])) - 5} more)"
            vulns = ', '.join(result.get('vulns', [])[:3])
            if len(result.get('vulns', [])) > 3:
                vulns += f" (+{len(result.get('vulns', [])) - 3} more)"
            hostnames = ', '.join(result.get('hostnames', [])[:2])
            if len(result.get('hostnames', [])) > 2:
                hostnames += "..."
            
            # Get location
            location = "N/A"
            if result.get('geolocation'):
                geo = result['geolocation']
                if geo.get('city') and geo.get('country'):
                    location = f"{geo['city']}, {geo['country']}"
                elif geo.get('country'):
                    location = geo['country']
            
            risk_class = risk.lower()
            rows.append(f"""
                <tr>
                    <td>{ip}</td>
                    <td><span class="badge {risk_class}">{risk}</span></td>
                    <td>{severity}</td>
                    <td>{ports or 'None'}</td>
                    <td>{vulns or 'None'}</td>
                    <td>{hostnames or 'None'}</td>
                    <td>{location}</td>
                </tr>
            """)
        
        return ''.join(rows)

