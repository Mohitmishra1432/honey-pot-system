const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const net = require('net');
const geoip = require('geoip-lite');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const moment = require('moment-timezone');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const db = new sqlite3.Database('logs.db');
db.run(`CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT,
  ip TEXT,
  activity TEXT,
  threat_level TEXT,
  city TEXT,
  country TEXT,
  port INTEGER,
  protocol TEXT,
  user_agent TEXT,
  payload TEXT,
  duration REAL,
  bytes INTEGER,
  asn TEXT,
  referrer TEXT,
  session_id TEXT,
  resource TEXT,
  category TEXT,
  first_seen TEXT,
  lat REAL,
  lon REAL,
  method TEXT,
  response TEXT,
  malware_hash TEXT,
  exploit_signature TEXT,
  attack_vector TEXT,
  command_history TEXT,
  bandwidth_rate REAL,
  dns_lookup TEXT,
  packet_count INTEGER,
  attacker_os TEXT,
  honeypot_type TEXT,
  alert_status TEXT,
  threat_score INTEGER,
  correlation_id TEXT,
  timestamp_local TEXT
)`, (err) => {
  if (err) console.error('Database creation error:', err.message);
  else console.log('Database initialized');
});

let loginAttempts = {};
let firstSeen = {};

function getClientIP(reqOrSocket) {
  let ip = reqOrSocket.remoteAddress || reqOrSocket.headers?.['x-forwarded-for']?.split(',')[0] || reqOrSocket.ip;
  return ip ? ip.replace('::ffff:', '').replace('::1', '127.0.0.1') : 'Unknown';
}

function getLocation(ip) {
  const geo = geoip.lookup(ip);
  return {
    city: geo?.city || 'Unknown',
    country: geo?.country || 'Unknown',
    asn: geo?.asn || 'Unknown',
    lat: geo?.ll?.[0] || 0,
    lon: geo?.ll?.[1] || 0
  };
}

function inferOSFromUserAgent(userAgent) {
  if (userAgent.includes('Windows')) return 'Windows';
  if (userAgent.includes('Linux')) return 'Linux';
  if (userAgent.includes('Mac')) return 'Mac';
  return 'Unknown';
}

function getThreatScore(threatLevel) {
  return { 'HIGH': 100, 'MEDIUM': 50, 'LOW': 10 }[threatLevel] || 0;
}

const tcpServer = net.createServer((socket) => {
  const ip = getClientIP(socket);
  const startTime = Date.now();
  const sessionId = uuidv4();
  console.log(`DEBUG: TCP connection from ${ip}`);

  const timestamp = new Date().toISOString();
  const activity = 'TCP Connection Attempt';
  const threat_level = 'MEDIUM'; // Changed to match schema
  const { city, country, asn, lat, lon } = getLocation(ip);
  const first_seen = firstSeen[ip] || timestamp; // Changed to match schema
  firstSeen[ip] = first_seen;

  let bytes = 0;
  let command_history = '';
  let packet_count = 0;

  socket.on('data', (data) => {
    bytes += data.length;
    command_history += data.toString();
    packet_count++;
    console.log(`DEBUG: Received data from ${ip}: ${data.toString()}`);
  });

  socket.on('end', () => {
    const duration = (Date.now() - startTime) / 1000;
    const bandwidth_rate = duration ? bytes / duration : 0;
    const attacker_os = 'Unknown';
    const honeypot_type = 'Telnet';
    const alert_status = 'Not Alerted';
    const threat_score = getThreatScore(threat_level);
    const correlation_id = ip;
    const timestamp_local = moment(timestamp).tz('America/Los_Angeles').format();

    const logEntry = {
      timestamp, ip, activity, threat_level, city, country, port: 23, protocol: 'TCP', user_agent: 'N/A', payload: command_history || 'N/A',
      duration, bytes, asn, referrer: 'N/A', session_id: sessionId, resource: 'N/A', category: 'Recon', first_seen, lat, lon, method: 'N/A', response: 'Connection Closed',
      malware_hash: 'N/A', exploit_signature: 'N/A', attack_vector: 'Telnet', command_history, bandwidth_rate, dns_lookup: 'N/A', packet_count, attacker_os, honeypot_type, alert_status, threat_score, correlation_id, timestamp_local
    };

    db.run(`INSERT INTO logs (${Object.keys(logEntry).join(', ')}) VALUES (${Object.keys(logEntry).map(() => '?').join(', ')})`,
      Object.values(logEntry),
      (err) => {
        if (err) console.error('TCP log insert error:', err.message);
        else {
          console.log(`Logged TCP attempt from ${ip}, ${city}, ${country}`);
          io.emit('newLog', logEntry);
        }
      });
  });

  socket.on('error', (err) => console.error(`TCP socket error from ${ip}:`, err.message));
  socket.end();
});

tcpServer.listen(23, () => console.log('TCP server listening on port 23'));
tcpServer.on('error', (err) => {
  console.error('TCP server error:', err.message);
  console.log('Trying fallback port 2323...');
  tcpServer.listen(2323, () => console.log('TCP server listening on fallback port 2323'));
});

app.all('/login', (req, res) => {
  const ip = getClientIP(req);
  const startTime = Date.now();
  const sessionId = uuidv4();
  console.log(`DEBUG: Login request from ${ip}`);

  const timestamp = new Date().toISOString();
  let activity = 'Login Page Access Attempt';
  let threat_level = 'LOW';
  const { city, country, asn, lat, lon } = getLocation(ip);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const referrer = req.headers['referer'] || 'N/A';
  const method = req.method;
  const payload = method === 'POST' ? (req.body.user || '') : 'N/A';
  const resource = '/login';
  const first_seen = firstSeen[ip] || timestamp;
  firstSeen[ip] = first_seen;

  let category = 'Recon';
  let exploit_signature = 'N/A';
  if (payload.match(/['";-]|OR|SELECT|UNION/i)) {
    activity = 'SQL Injection Attempt';
    threat_level = 'HIGH';
    category = 'Exploit';
    exploit_signature = 'SQL Injection';
  } else if (payload.includes(';') || payload.match(/dir|cmd|rm/i)) {
    activity = 'Command Injection Attempt';
    threat_level = 'HIGH';
    category = 'Exploit';
    exploit_signature = 'Command Injection';
  } else if (payload.includes('<script>') || payload.includes('alert')) {
    activity = 'XSS Attempt';
    threat_level = 'HIGH';
    category = 'Exploit';
    exploit_signature = 'XSS';
  } else if (method === 'POST') {
    loginAttempts[ip] = (loginAttempts[ip] || 0) + 1;
    if (loginAttempts[ip] > 2) {
      activity = 'Credential Stuffing Attempt';
      threat_level = 'MEDIUM';
      category = 'Brute Force';
    }
    setTimeout(() => { loginAttempts[ip] = 0; }, 10000);
  }

  const responseText = '<h1>Fake Login</h1><form method="POST"><input name="user"><input name="pass" type="password"><button>Login</button></form>';
  const duration = (Date.now() - startTime) / 1000;
  const bytes = Buffer.byteLength(responseText) + (payload.length || 0);
  const bandwidth_rate = duration ? bytes / duration : 0;
  const attacker_os = inferOSFromUserAgent(userAgent);
  const honeypot_type = 'Web Login';
  const alert_status = threat_level === 'HIGH' ? 'Alerted' : 'Not Alerted';
  const threat_score = getThreatScore(threat_level);
  const correlation_id = ip;
  const timestamp_local = moment(timestamp).tz('America/Los_Angeles').format();

  const logEntry = {
    timestamp, ip, activity, threat_level, city, country, port: 3000, protocol: 'HTTP', user_agent: userAgent, payload,
    duration, bytes, asn, referrer, session_id: sessionId, resource, category, first_seen, lat, lon, method, response: 'Login Page Served',
    malware_hash: 'N/A', exploit_signature, attack_vector: 'Web Login Form', command_history: 'N/A', bandwidth_rate, dns_lookup: 'N/A', packet_count: 1, attacker_os, honeypot_type, alert_status, threat_score, correlation_id, timestamp_local
  };

  db.run(`INSERT INTO logs (${Object.keys(logEntry).join(', ')}) VALUES (${Object.keys(logEntry).map(() => '?').join(', ')})`,
    Object.values(logEntry),
    (err) => {
      if (err) console.error('Login log insert error:', err.message);
      else {
        console.log(`Logged ${activity} from ${ip}, ${city}, ${country}`);
        io.emit('newLog', logEntry);
      }
    });

  res.send(responseText);
});

app.get('/logs', (req, res) => {
  console.log('DEBUG: Fetching logs from database');
  db.all('SELECT * FROM logs ORDER BY timestamp DESC', (err, rows) => {
    if (err) {
      console.error('Log fetch error:', err.message);
      res.status(500).send(err.message);
    } else {
      console.log(`DEBUG: Sending ${rows.length} logs to client`);
      res.json(rows);
    }
  });
});

server.listen(3000, () => console.log('Web server running on port 3000'));