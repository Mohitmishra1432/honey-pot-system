const socket = io('http://localhost:3000');
let lastLogId = 0;
let logs = [];

function renderLogs(newLogs) {
  console.log('DEBUG: Rendering logs:', newLogs);
  logs = newLogs;
  const tbody = document.getElementById('logs-body');
  const newLogEntries = logs.filter(log => log.id > lastLogId);
  if (newLogEntries.length > 0) {
    newLogEntries.forEach(log => {
      const row = document.createElement('tr');
      row.classList.add('new-log');
      row.innerHTML = `
        <td>${log.timestamp}</td>
        <td class="ip-address" onclick="showIPDetails('${log.ip}')">${log.ip || 'Unknown'}</td>
        <td>${log.activity}</td>
        <td class="${log.threat_level === 'HIGH' ? 'alert' : ''}">${log.threat_level}</td>
        <td>${log.city}, ${log.country}</td>
        <td>${log.port}</td>
        <td>${log.protocol}</td>
        <td>${log.category}</td>
        <td><button class="btn btn-sm btn-secondary" onclick="showDetails('${log.id}')">Details</button></td>
      `;
      tbody.insertBefore(row, tbody.firstChild);
      lastLogId = Math.max(lastLogId, log.id);
      setTimeout(() => row.classList.remove('new-log'), 2000);
    });
  }
}

async function fetchLogs() {
  try {
    console.log('DEBUG: Fetching logs from /logs');
    const response = await fetch('/logs');
    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
    const logsData = await response.json();
    renderLogs(logsData);
    renderMap(logsData);
  } catch (error) {
    console.error('Fetch logs error:', error.message);
  }
}

function clearLogs() {
  if (confirm('Clear all logs from view? (Server data persists)')) {
    document.getElementById('logs-body').innerHTML = '';
    lastLogId = 0;
    fetchLogs();
  }
}

function exportLogs() {
  const dataStr = JSON.stringify(logs, null, 2);
  const blob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `honeypot_logs_${new Date().toISOString()}.json`;
  link.click();
}

function showIPDetails(ip) {
  const ipLogs = logs.filter(log => log.ip === ip);
  const attempts = ipLogs.length;
  const lastSeen = ipLogs[0].timestamp;
  const location = `${ipLogs[0].city}, ${ipLogs[0].country}`;
  alert(`IP: ${ip}\nAttempts: ${attempts}\nLast Seen: ${lastSeen}\nLocation: ${location}\nFirst Seen: ${ipLogs[0].first_seen}`);
}

function showDetails(logId) {
  const log = logs.find(log => log.id == logId);
  if (log) {
    const detailsHtml = Object.entries(log).map(([key, value]) => `<strong>${key}:</strong> ${value}`).join('<br>');
    document.getElementById('detailsModalBody').innerHTML = detailsHtml;
    new bootstrap.Modal(document.getElementById('detailsModal')).show();
  }
}

let map;
function initMap() {
  map = L.map('map').setView([0, 0], 2);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
  }).addTo(map);
}

function renderMap(logs) {
  map.eachLayer(layer => { if (layer instanceof L.Marker) map.removeLayer(layer); });
  const uniqueIPs = {};
  logs.forEach(log => {
    if (!uniqueIPs[log.ip] && log.lat !== 0 && log.lon !== 0) {
      uniqueIPs[log.ip] = { lat: log.lat, lon: log.lon, city: log.city, country: log.country };
    }
  });
  Object.entries(uniqueIPs).forEach(([ip, loc]) => {
    const marker = L.marker([loc.lat, loc.lon]).addTo(map);
    marker.bindPopup(`<strong>IP:</strong> ${ip}<br><strong>Location:</strong> ${loc.city}, ${loc.country}<br><strong>Attempts:</strong> ${logs.filter(l => l.ip === ip).length}`);
  });
}

initMap();
fetchLogs();

socket.on('newLog', (log) => {
  console.log('DEBUG: New log received via socket:', log);
  logs.unshift(log);
  renderLogs(logs);
  renderMap(logs);
});

socket.on('connect_error', (err) => console.error('Socket.io connection error:', err.message));