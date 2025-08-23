const http = require('http');
const WebSocket = require('ws');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Безопасная загрузка модулей с обработкой ошибок
let pool, initDatabase, Message, User;

try {
  const dbInit = require('./db/init');
  pool = dbInit.pool;
  initDatabase = dbInit.initDatabase;
} catch (error) {
  console.error('❌ Error loading db/init:', error);
  process.exit(1);
}

try {
  Message = require('./Message');
} catch (error) {
  console.error('❌ Error loading Message module:', error);
  process.exit(1);
}

try {
  User = require('./User');
} catch (error) {
  console.error('❌ Error loading User module:', error);
  process.exit(1);
}

dotenv.config({ path: path.resolve(__dirname, '.env') });

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

if (!DATABASE_URL) {
  console.error('❌ Переменная окружения DATABASE_URL не задана. Добавьте ее в .env');
  process.exit(1);
}

// Инициализация базы данных
async function startServer() {
  try {
    await initDatabase();
    console.log('✅ База данных PostgreSQL инициализирована');
    
    // HTTP server (Express)
    const app = express();
    app.use(cors({
      origin: true, // Разрешить все домены для тестирования
      credentials: true
    }));
    app.use(express.json());
    
    // Simple request logging
    app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const ms = Date.now() - start;
        console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} ${ms}ms`);
      });
      next();
    });

    // Validation functions
    function validateUsername(username) {
      if (!username || typeof username !== 'string') {
        return { valid: false, error: 'Username is required' };
      }
      
      const trimmed = username.trim();
      if (trimmed.length < 3 || trimmed.length > 20) {
        return { valid: false, error: 'Username must be between 3 and 20 characters' };
      }
      
      // Only Latin letters allowed
      if (!/^[a-zA-Z]+$/.test(trimmed)) {
        return { valid: false, error: 'Username can only contain Latin letters' };
      }
      
      return { valid: true, username: trimmed };
    }

    function validatePassword(password) {
      if (!password || typeof password !== 'string') {
        return { valid: false, error: 'Password is required' };
      }
      
      if (password.length < 4 || password.length > 10) {
        return { valid: false, error: 'Password must be between 4 and 10 characters' };
      }
      
      // Only digits allowed
      if (!/^\d+$/.test(password)) {
        return { valid: false, error: 'Password can only contain digits' };
      }
      
      return { valid: true, password };
    }

    // Lightweight health check to help with warmups
    app.get('/api/health', (_req, res) => {
      res.json({ 
        ok: true, 
        uptime: process.uptime(),
        websocket: {
          connectedClients: wss.clients.size,
          server: 'running'
        }
      });
    });

    // WebSocket status endpoint
    app.get('/api/websocket/status', (_req, res) => {
      res.json({
        status: 'running',
        connectedClients: wss.clients.size,
        uptime: process.uptime()
      });
    });

    // Auth: Register
    app.post('/api/auth/register', async (req, res) => {
      console.log('📝 Registration request received:', { 
        body: req.body, 
        headers: req.headers,
        timestamp: new Date().toISOString()
      });
      
      try {
        const { username, password } = req.body || {};
        
        // Validate username
        const usernameValidation = validateUsername(username);
        if (!usernameValidation.valid) {
          console.log('❌ Username validation failed:', usernameValidation.error);
          return res.status(400).json({ error: usernameValidation.error });
        }
        
        // Validate password
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
          console.log('❌ Password validation failed:', passwordValidation.error);
          return res.status(400).json({ error: passwordValidation.error });
        }
        
        console.log('🔍 Checking for existing user...');
        const usernameLower = usernameValidation.username.toLowerCase();
        const existing = await User.findOne({ usernameLower });
        if (existing) {
          console.log('❌ Username already taken:', usernameLower);
          return res.status(409).json({ error: 'Username already taken' });
        }
        
        console.log('🔐 Hashing password...');
        const passwordHash = await bcrypt.hash(passwordValidation.password, 6);
        
        console.log('💾 Creating user...');
        const user = await User.create({ 
          username: usernameValidation.username, 
          usernameLower, 
          passwordHash 
        });
        
        console.log('✅ User created successfully:', { id: user.id, username: user.username });
        return res.status(201).json({ id: user.id, username: user.username, createdAt: user.created_at });
      } catch (e) {
        console.error('❌ Register error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Auth: Login
    app.post('/api/auth/login', async (req, res) => {
      console.log('🔐 Login request received:', { 
        body: req.body, 
        timestamp: new Date().toISOString()
      });
      
      try {
        const { username, password } = req.body || {};
        
        // Validate username
        const usernameValidation = validateUsername(username);
        if (!usernameValidation.valid) {
          console.log('❌ Username validation failed:', usernameValidation.error);
          return res.status(400).json({ error: usernameValidation.error });
        }
        
        // Validate password
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
          console.log('❌ Password validation failed:', passwordValidation.error);
          return res.status(400).json({ error: passwordValidation.error });
        }
        
        const usernameLower = usernameValidation.username.toLowerCase();
        const user = await User.findOne({ usernameLower });
        if (!user) {
          console.log('❌ User not found:', usernameLower);
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const ok = await bcrypt.compare(passwordValidation.password, user.password_hash);
        if (!ok) {
          console.log('❌ Invalid password for user:', usernameLower);
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check if user is blocked
        if (user.is_blocked) {
          console.log('❌ Blocked user tried to login:', usernameLower);
          return res.status(403).json({ 
            error: 'Account blocked', 
            reason: user.block_reason || 'No reason provided' 
          });
        }
        
        // Update login stats
        const client = await pool.connect();
        try {
          await client.query(`
            UPDATE users 
            SET last_login_at = $1, login_count = $2
            WHERE id = $3
          `, [new Date(), user.login_count + 1, user.id]);
        } finally {
          client.release();
        }
        
        const token = jwt.sign({ sub: String(user.id) }, JWT_SECRET, { expiresIn: '7d' });
        console.log('✅ Login successful for user:', usernameLower);
        return res.json({ 
          token, 
          user: { 
            id: user.id, 
            username: user.username,
            isAdmin: user.is_admin 
          } 
        });
      } catch (e) {
        console.error('❌ Login error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Users list (public)
    app.get('/api/users', async (_req, res) => {
      try {
        const users = await User.find({}, { username: 1, createdAt: 1 });
        return res.json(users.map((u) => ({ 
          id: u.id, 
          username: u.username,
          createdAt: u.created_at 
        })));
      } catch (e) {
        console.error('❌ Users list error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Helper function to get user from token
    async function getUserFromToken(req) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
      }
      
      const token = authHeader.substring(7);
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.sub);
        return user;
      } catch (jwtError) {
        return null;
      }
    }

    // Clear all users (no auth required for testing)
    app.post('/api/users/clear-all', async (req, res) => {
      try {
        // Сначала получаем всех пользователей для логирования
        const allUsers = await User.find({});
        console.log(`🗑️ Found ${allUsers.length} users to delete`);
        
        // Удаляем всех пользователей, кроме админа
        const result = await User.deleteMany({ 
          usernameLower: { $ne: 'uyqidioiw' } // Не удаляем админа
        });
        
        console.log(`🗑️ Cleared ${result.deletedCount} users (admin preserved)`);
        
        return res.json({ 
          message: `Cleared ${result.deletedCount} users (admin preserved)`,
          deletedCount: result.deletedCount,
          totalFound: allUsers.length
        });
      } catch (e) {
        console.error('❌ Clear users error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Get chat messages
    app.get('/api/chat/:chatId', async (req, res) => {
      try {
        const { chatId } = req.params;
        const messages = await Message.find({ chatId });
        
        // Нормализуем сообщения для совместимости с клиентами
        const normalizedMessages = messages.map(msg => ({
          _id: msg.id,
          id: msg.id,
          username: msg.username,
          text: msg.text,
          chatId: msg.chat_id, // Преобразуем chat_id в chatId
          timestamp: msg.timestamp
        }));
        
        return res.json(normalizedMessages);
      } catch (e) {
        console.error('❌ Get chat messages error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Send message (HTTP endpoint for testing)
    app.post('/api/chat/send', async (req, res) => {
      try {
        const { username, text, chatId, replyTo } = req.body;
        
        if (!username || !text || !chatId) {
          return res.status(400).json({ error: 'Missing required fields' });
        }
        
        // Проверяем, существует ли сообщение, на которое отвечаем
        let replyToMessage = null;
        if (replyTo && replyTo.messageId) {
          replyToMessage = await Message.findById(replyTo.messageId);
          if (!replyToMessage) {
            return res.status(400).json({ error: 'Reply message not found' });
          }
        }
        
        const msg = await Message.create({
          username,
          text,
          chatId,
          replyTo: replyToMessage ? replyToMessage.id : null
        });

        // Нормализуем поля для совместимости с клиентами
        const normalizedMsg = {
          _id: msg.id,
          id: msg.id, // Добавляем id для совместимости с веб-клиентом
          username: msg.username,
          text: msg.text,
          chatId: msg.chat_id, // Преобразуем chat_id в chatId
          timestamp: msg.timestamp,
          replyTo: msg.replyTo ? {
            id: msg.replyTo.id,
            username: msg.replyTo.username,
            text: msg.replyTo.text,
            timestamp: msg.replyTo.timestamp
          } : null
        };

        // Broadcast to all websocket clients, same as realtime flow
        try {
          const outgoing = JSON.stringify({ type: 'message', message: normalizedMsg });
          wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(outgoing);
            }
          });
        } catch (broadcastErr) {
          console.error('⚠️ Broadcast error after HTTP send:', broadcastErr);
        }

        return res.json({ message: 'Message sent successfully', msg: normalizedMsg });
      } catch (e) {
        console.error('❌ Send message error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Admin: Get all users with details (admin only)
    app.get('/api/admin/users', async (req, res) => {
      try {
        const user = await getUserFromToken(req);
        if (!user || !user.is_admin) {
          return res.status(403).json({ error: 'Admin access required' });
        }
        
        const users = await User.find({});
        
        return res.json(users.map(u => ({
          id: u.id,
          username: u.username,
          isAdmin: u.is_admin,
          isBlocked: u.is_blocked,
          blockReason: u.block_reason,
          lastLoginAt: u.last_login_at,
          loginCount: u.login_count,
          createdAt: u.created_at,
          updatedAt: u.updated_at
        })));
      } catch (e) {
        console.error('❌ Admin users list error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Admin: Block/Unblock user
    app.post('/api/admin/users/:userId/block', async (req, res) => {
      try {
        const admin = await getUserFromToken(req);
        if (!admin || !admin.is_admin) {
          return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { userId } = req.params;
        const { isBlocked, reason = '' } = req.body;
        
        if (typeof isBlocked !== 'boolean') {
          return res.status(400).json({ error: 'isBlocked must be boolean' });
        }
        
        const targetUser = await User.findById(userId);
        if (!targetUser) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        // Prevent admin from blocking themselves
        if (targetUser.id.toString() === admin.id.toString()) {
          return res.status(400).json({ error: 'Cannot block yourself' });
        }
        
        targetUser.is_blocked = isBlocked;
        targetUser.block_reason = reason;
        await targetUser.save();
        
        console.log(`🔒 ${isBlocked ? 'Blocked' : 'Unblocked'} user: ${targetUser.username}`);
        
        return res.json({ 
          message: `User ${isBlocked ? 'blocked' : 'unblocked'} successfully`,
          user: {
            id: targetUser.id,
            username: targetUser.username,
            isBlocked: targetUser.is_blocked,
            blockReason: targetUser.block_reason
          }
        });
      } catch (e) {
        console.error('❌ Block user error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Admin: Delete user
    app.delete('/api/admin/users/:userId', async (req, res) => {
      try {
        const admin = await getUserFromToken(req);
        if (!admin || !admin.is_admin) {
          return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { userId } = req.params;
        
        const targetUser = await User.findById(userId);
        if (!targetUser) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        // Prevent admin from deleting themselves
        if (targetUser.id.toString() === admin.id.toString()) {
          return res.status(400).json({ error: 'Cannot delete yourself' });
        }
        
        await User.findByIdAndDelete(userId);
        
        console.log(`🗑️ Deleted user: ${targetUser.username}`);
        
        return res.json({ 
          message: 'User deleted successfully',
          deletedUser: {
            id: targetUser.id,
            username: targetUser.username
          }
        });
      } catch (e) {
        console.error('❌ Delete user error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Admin: Make user admin
    app.post('/api/admin/users/:userId/admin', async (req, res) => {
      try {
        const admin = await getUserFromToken(req);
        if (!admin || !admin.is_admin) {
          return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { userId } = req.params;
        const { isAdmin } = req.body;
        
        if (typeof isAdmin !== 'boolean') {
          return res.status(400).json({ error: 'isAdmin must be boolean' });
        }
        
        const targetUser = await User.findById(userId);
        if (!targetUser) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        targetUser.is_admin = isAdmin;
        await targetUser.save();
        
        console.log(`👑 ${isAdmin ? 'Made' : 'Removed'} admin: ${targetUser.username}`);
        
        return res.json({ 
          message: `User ${isAdmin ? 'made' : 'removed from'} admin successfully`,
          user: {
            id: targetUser.id,
            username: targetUser.username,
            isAdmin: targetUser.is_admin
          }
        });
      } catch (e) {
        console.error('❌ Admin user error:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    });

    const server = http.createServer(app);
    const wss = new WebSocket.Server({ server, path: '/ws' });

    // Keepalive ping to prevent idle disconnects on hosting providers
    function heartbeat() {
      this.isAlive = true;
    }

    wss.on('connection', async (ws, req) => {
      console.log('🔌 Новый клиент подключился');
      
      // Логируем подключение в базу данных
      try {
        const client = await pool.connect();
        await client.query(`
          INSERT INTO websocket_logs (event_type, details, timestamp)
          VALUES ($1, $2, $3)
        `, ['connection', `Client connected from ${req.socket.remoteAddress}`, new Date()]);
        client.release();
      } catch (logErr) {
        console.error('⚠️ Ошибка логирования подключения:', logErr);
      }
      
      ws.isAlive = true;
      ws.on('pong', heartbeat);

      // Отправляем приветственное сообщение
      try {
        const welcomeMsg = JSON.stringify({ 
          type: 'connection', 
          message: 'Connected successfully',
          timestamp: new Date().toISOString()
        });
        ws.send(welcomeMsg);
      } catch (err) {
        console.error('⚠️ Ошибка отправки приветственного сообщения:', err);
      }

      ws.on('message', async (data) => {
        try {
          const text = typeof data === 'string' ? data : data.toString();
          console.log('📨 Получено WebSocket сообщение:', text);
          
          const parsed = JSON.parse(text); // { username, text, chatId, id? }

          if (!parsed?.username || !parsed?.text || !parsed?.chatId) {
            console.warn('⚠️ Неполное сообщение:', parsed);
            // Отправляем ошибку клиенту
            const errorMsg = JSON.stringify({ 
              type: 'error', 
              message: 'Invalid message format. Required fields: username, text, chatId',
              timestamp: new Date().toISOString()
            });
            ws.send(errorMsg);
            return;
          }

          console.log(`💬 Создаю сообщение от ${parsed.username}: ${parsed.text}`);

          // Проверяем, есть ли ответ на сообщение
          let replyToMessage = null;
          if (parsed.replyTo && parsed.replyTo.messageId) {
            replyToMessage = await Message.findById(parsed.replyTo.messageId);
            if (!replyToMessage) {
              console.warn('⚠️ Reply message not found:', parsed.replyTo.messageId);
            }
          }
          
          const msg = await Message.create({
            username: parsed.username,
            text: parsed.text,
            chatId: parsed.chatId,
            replyTo: replyToMessage ? replyToMessage.id : null
          });

          // Нормализуем поля для совместимости с клиентами
          const normalizedMsg = {
            _id: msg.id,
            id: parsed.id || msg.id, // Используем ID от клиента или генерируем новый
            username: msg.username,
            text: msg.text,
            chatId: msg.chat_id, // Преобразуем chat_id в chatId
            timestamp: msg.timestamp,
            replyTo: msg.replyTo ? {
              id: msg.replyTo.id,
              username: msg.replyTo.username,
              text: msg.replyTo.text,
              timestamp: msg.replyTo.timestamp
            } : null
          };

          const outgoing = JSON.stringify({ type: 'message', message: normalizedMsg });
          console.log(`📤 Отправляю сообщение всем клиентам: ${outgoing}`);
          
          // Отправляем сообщение всем подключенным клиентам
          let sentCount = 0;
          wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
              try {
                client.send(outgoing);
                sentCount++;
              } catch (sendErr) {
                console.error('⚠️ Ошибка отправки сообщения клиенту:', sendErr);
              }
            }
          });
          
          console.log(`✅ Сообщение отправлено ${sentCount} клиентам`);
          
          // Логируем успешную отправку
          try {
            const client = await pool.connect();
            await client.query(`
              INSERT INTO websocket_logs (event_type, details, timestamp)
              VALUES ($1, $2, $3)
            `, ['message_sent', `Message from ${parsed.username} sent to ${sentCount} clients`, new Date()]);
            client.release();
          } catch (logErr) {
            console.error('⚠️ Ошибка логирования сообщения:', logErr);
          }
          
          // Отправляем подтверждение отправителю
          const confirmation = JSON.stringify({ 
            type: 'message_sent', 
            messageId: msg.id,
            timestamp: new Date().toISOString()
          });
          ws.send(confirmation);
          
        } catch (err) {
          console.error('⚠️ Ошибка обработки сообщения:', err);
          // Отправляем ошибку клиенту
          const errorMsg = JSON.stringify({ 
            type: 'error', 
            message: 'Failed to process message',
            timestamp: new Date().toISOString()
          });
          ws.send(errorMsg);
        }
      });

      ws.on('close', (code, reason) => {
        console.log(`❌ Клиент отключился: код=${code}, причина=${reason}`);
        
        // Логируем отключение
        pool.connect().then(client => {
          client.query(`
            INSERT INTO websocket_logs (event_type, details, timestamp)
            VALUES ($1, $2, $3)
          `, ['disconnection', `Client disconnected: code=${code}, reason=${reason}`, new Date()]);
          client.release();
        }).catch(logErr => {
          console.error('⚠️ Ошибка логирования отключения:', logErr);
        });
      });
      
      ws.on('error', (error) => {
        console.error('💥 WebSocket ошибка:', error);
        
        // Логируем ошибку
        pool.connect().then(client => {
          client.query(`
            INSERT INTO websocket_logs (event_type, details, timestamp)
            VALUES ($1, $2, $3)
          `, ['error', `WebSocket error: ${error.message}`, new Date()]);
          client.release();
        }).catch(logErr => {
          console.error('⚠️ Ошибка логирования ошибки:', logErr);
        });
      });
    });

    const interval = setInterval(() => {
      wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        try {
          ws.ping();
        } catch (_) {}
      });
    }, 30000);

    wss.on('close', function close() {
      clearInterval(interval);
    });

    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Сервер запущен на порту ${PORT}`);
      console.log(`🌐 Доступен по адресу: http://192.168.0.83:${PORT}`);
      console.log(`🔒 Локальный доступ: http://localhost:${PORT}`);
    });

  } catch (error) {
    console.error('💥 Ошибка запуска сервера:', error);
    process.exit(1);
  }
}

startServer();
