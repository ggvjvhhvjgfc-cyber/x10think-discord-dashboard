#!/usr/bin/env node

/**
 * ============================================
 * X10THINK Discord Dashboard Backend
 * Server Completo - All in One
 * ============================================
 * 
 * تشغيل:
 * node server.js
 * 
 * أو للتطوير:
 * nodemon server.js
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv';

// ============================================
// SETUP
// ============================================

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dataDir = path.join(__dirname, 'data');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const PORT = process.env.PORT || 5000;
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.FRONTEND_URL 
      : ['http://localhost:3000', 'http://127.0.0.1:3000', '*'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  }
});

// ============================================
// UTILITIES
// ============================================

const loadJSON = (filename) => {
  const filePath = path.join(dataDir, filename);
  if (!fs.existsSync(filePath)) return {};
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return {};
  }
};

const saveJSON = (filename, data) => {
  const filePath = path.join(dataDir, filename);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
};

const generateId = () => `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

// ============================================
// MIDDLEWARE
// ============================================

app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL 
    : '*',
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

app.use('/api/', limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ success: false, message: 'Invalid token' });
  }
};

// ============================================
// ROUTES - AUTH
// ============================================

app.get('/api/auth/login', (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirectUri = encodeURIComponent(process.env.DISCORD_REDIRECT_URI || 'http://localhost:3000/api/auth/callback');
  const scope = encodeURIComponent('identify email guilds');
  
  const authUrl = `https://discord.com/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}`;
  
  res.json({ success: true, authUrl });
});

app.get('/api/auth/callback', async (req, res) => {
  const { code } = req.query;
  
  if (!code) {
    return res.status(400).json({ success: false, message: 'No code provided' });
  }
  
  try {
    const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', 
      new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: process.env.DISCORD_REDIRECT_URI || 'http://localhost:3000/api/auth/callback',
        scope: 'identify email guilds'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    
    const { access_token } = tokenResponse.data;
    
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });
    
    const userData = userResponse.data;
    
    const guildsResponse = await axios.get('https://discord.com/api/users/@me/guilds', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });
    
    const managedGuilds = guildsResponse.data.filter(guild => 
      (guild.permissions & 0x8) === 0x8
    );
    
    const users = loadJSON('users.json');
    users[userData.id] = {
      id: userData.id,
      username: userData.username,
      discriminator: userData.discriminator,
      avatar: userData.avatar,
      email: userData.email,
      managedGuilds,
      lastLogin: new Date().toISOString()
    };
    saveJSON('users.json', users);
    
    const token = jwt.sign(
      { userId: userData.id, username: userData.username },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );
    
    const frontendUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/callback?token=${token}&userId=${userData.id}`;
    res.redirect(frontendUrl);
    
  } catch (error) {
    console.error('OAuth error:', error.message);
    res.status(500).json({ success: false, message: 'Authentication failed' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const users = loadJSON('users.json');
    const user = users[decoded.userId];
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
        email: user.email,
        managedGuilds: user.managedGuilds
      }
    });
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// ============================================
// ROUTES - DASHBOARD
// ============================================

app.get('/api/dashboard/overview/:serverId', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  
  res.json({
    success: true,
    data: {
      serverName: 'Server Name',
      memberCount: 1250,
      botCount: 15,
      channelCount: 45,
      roleCount: 32,
      ticketCount: 128,
      warningCount: 45,
      botStatus: 'online'
    }
  });
});

app.get('/api/dashboard/stats/:serverId', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { period = 'day' } = req.query;
  
  res.json({
    success: true,
    data: {
      period,
      totalMembers: 1250,
      activeMembers: 450,
      newMembers: 25,
      leftMembers: 5,
      topMembers: [],
      topStaff: []
    }
  });
});

app.get('/api/dashboard/analytics/:serverId', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: {
      memberGrowth: [],
      messageActivity: [],
      voiceActivity: [],
      ticketActivity: [],
      moderationActivity: []
    }
  });
});

// ============================================
// ROUTES - MODERATION
// ============================================

app.post('/api/moderation/:serverId/ban', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { userId, reason, deleteDays = 0 } = req.body;
  
  const modLogs = loadJSON(`moderation_${serverId}.json`);
  modLogs[generateId()] = {
    action: 'ban',
    target: userId,
    moderator: req.user.id,
    reason,
    deleteDays,
    timestamp: new Date().toISOString()
  };
  saveJSON(`moderation_${serverId}.json`, modLogs);
  
  res.json({ success: true, message: 'User banned successfully' });
});

app.post('/api/moderation/:serverId/kick', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { userId, reason } = req.body;
  
  const modLogs = loadJSON(`moderation_${serverId}.json`);
  modLogs[generateId()] = {
    action: 'kick',
    target: userId,
    moderator: req.user.id,
    reason,
    timestamp: new Date().toISOString()
  };
  saveJSON(`moderation_${serverId}.json`, modLogs);
  
  res.json({ success: true, message: 'User kicked successfully' });
});

app.post('/api/moderation/:serverId/timeout', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { userId, duration, reason } = req.body;
  
  const modLogs = loadJSON(`moderation_${serverId}.json`);
  modLogs[generateId()] = {
    action: 'timeout',
    target: userId,
    moderator: req.user.id,
    duration,
    reason,
    timestamp: new Date().toISOString()
  };
  saveJSON(`moderation_${serverId}.json`, modLogs);
  
  res.json({ success: true, message: 'Timeout applied successfully' });
});

app.post('/api/moderation/:serverId/warn', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { userId, reason } = req.body;
  
  const modLogs = loadJSON(`moderation_${serverId}.json`);
  modLogs[generateId()] = {
    action: 'warn',
    target: userId,
    moderator: req.user.id,
    reason,
    timestamp: new Date().toISOString()
  };
  saveJSON(`moderation_${serverId}.json`, modLogs);
  
  res.json({ success: true, message: 'Warning issued successfully' });
});

app.get('/api/moderation/:serverId/logs', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { limit = 50, offset = 0 } = req.query;
  
  const modLogs = loadJSON(`moderation_${serverId}.json`);
  const logs = Object.values(modLogs || {});
  
  res.json({
    success: true,
    data: {
      logs: logs.slice(offset, offset + limit),
      total: logs.length,
      limit: parseInt(limit),
      offset: parseInt(offset)
    }
  });
});

// ============================================
// ROUTES - TICKETS
// ============================================

app.post('/api/tickets/:serverId/system/create', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { name, type, settings } = req.body;
  
  const systems = loadJSON(`tickets_${serverId}.json`);
  const systemId = generateId();
  
  systems[systemId] = { name, type, settings, createdAt: new Date().toISOString() };
  saveJSON(`tickets_${serverId}.json`, systems);
  
  res.json({
    success: true,
    message: 'Ticket system created successfully',
    data: { systemId, name, type, settings }
  });
});

app.post('/api/tickets/:serverId/open', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { systemId, title, description } = req.body;
  
  const tickets = loadJSON(`tickets_open_${serverId}.json`);
  const ticketId = generateId();
  
  tickets[ticketId] = {
    systemId,
    title,
    description,
    userId: req.user.id,
    status: 'open',
    createdAt: new Date().toISOString(),
    messages: []
  };
  saveJSON(`tickets_open_${serverId}.json`, tickets);
  
  res.json({
    success: true,
    message: 'Ticket opened successfully',
    data: { ticketId, status: 'open', createdAt: new Date().toISOString() }
  });
});

app.post('/api/tickets/:serverId/:ticketId/close', authenticateToken, (req, res) => {
  const { serverId, ticketId } = req.params;
  const { reason } = req.body;
  
  const tickets = loadJSON(`tickets_open_${serverId}.json`);
  if (tickets[ticketId]) {
    tickets[ticketId].status = 'closed';
    tickets[ticketId].closedAt = new Date().toISOString();
    tickets[ticketId].closeReason = reason;
    saveJSON(`tickets_open_${serverId}.json`, tickets);
  }
  
  res.json({ success: true, message: 'Ticket closed successfully' });
});

// ============================================
// ROUTES - SERVER
// ============================================

app.get('/api/server/:serverId/info', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  
  res.json({
    success: true,
    data: {
      id: serverId,
      name: 'Server Name',
      memberCount: 0,
      botCount: 0,
      channelCount: 0,
      roleCount: 0,
      ticketCount: 0,
      warningCount: 0,
      botStatus: 'online'
    }
  });
});

app.get('/api/server/:serverId/members', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  const { limit = 50, offset = 0 } = req.query;
  
  res.json({
    success: true,
    data: {
      members: [],
      total: 0,
      limit: parseInt(limit),
      offset: parseInt(offset)
    }
  });
});

app.put('/api/server/:serverId/settings', authenticateToken, (req, res) => {
  const { serverId } = req.params;
  
  const settings = loadJSON(`server_settings_${serverId}.json`);
  const updated = { ...settings, ...req.body, updatedAt: new Date().toISOString() };
  saveJSON(`server_settings_${serverId}.json`, updated);
  
  res.json({ success: true, message: 'Server settings updated successfully' });
});

// ============================================
// ROUTES - HEALTH & INFO
// ============================================

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/api/info', (req, res) => {
  res.json({
    name: 'X10THINK Discord Dashboard',
    version: '1.0.0',
    status: 'operational',
    features: [
      'Authentication',
      'Moderation',
      'Tickets',
      'Analytics',
      'Server Management'
    ]
  });
});

// ============================================
// SOCKET.IO
// ============================================

io.on('connection', (socket) => {
  console.log('✓ Socket connected:', socket.id);
  
  socket.on('join-server', (serverId) => {
    socket.join(`server-${serverId}`);
    console.log(`  └─ User joined server: ${serverId}`);
  });
  
  socket.on('leave-server', (serverId) => {
    socket.leave(`server-${serverId}`);
    console.log(`  └─ User left server: ${serverId}`);
  });
  
  socket.on('disconnect', () => {
    console.log('✗ Socket disconnected:', socket.id);
  });
});

// ============================================
// ERROR HANDLERS
// ============================================

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// ============================================
// START SERVER
// ============================================

httpServer.listen(PORT, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`✅ X10THINK Discord Dashboard Backend`);
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💾 Data Directory: ${dataDir}`);
  console.log(`${'='.repeat(60)}\n`);
  console.log(`Health Check: http://localhost:${PORT}/health`);
  console.log(`API Info: http://localhost:${PORT}/api/info\n`);
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('\\nSIGTERM received, shutting down gracefully');
  httpServer.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

export { io };
export default app;
