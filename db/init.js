const { Pool } = require('pg');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

async function initDatabase() {
  const client = await pool.connect();
  
  try {
    console.log('🔌 Подключение к PostgreSQL...');
    
    // Создаем таблицу пользователей
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(20) NOT NULL,
        username_lower VARCHAR(20) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        is_blocked BOOLEAN DEFAULT FALSE,
        block_reason TEXT DEFAULT '',
        last_login_at TIMESTAMP,
        login_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Создаем таблицу сообщений
    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        username VARCHAR(20) NOT NULL,
        text TEXT NOT NULL,
        chat_id VARCHAR(255) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Создаем индексы для оптимизации
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(username_lower);
      CREATE INDEX IF NOT EXISTS idx_messages_chat_id_timestamp ON messages(chat_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
    `);
    
    // Создаем функцию для автоматического обновления updated_at
    await client.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);
    
    // Создаем триггер для автоматического обновления updated_at
    await client.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
    `);
    
    // Проверяем, существует ли админ пользователь
    const adminCheck = await client.query(
      'SELECT id FROM users WHERE username_lower = $1',
      ['uyqidioiw']
    );
    
    if (adminCheck.rows.length === 0) {
      const bcrypt = require('bcryptjs');
      const adminPasswordHash = await bcrypt.hash('606404', 6);
      
      await client.query(`
        INSERT INTO users (username, username_lower, password_hash, is_admin)
        VALUES ($1, $2, $3, $4)
      `, ['UyqidiOiw', 'uyqidioiw', adminPasswordHash, true]);
      
      console.log('👑 Admin user created: UyqidiOiw');
    } else {
      console.log('👑 Admin user already exists: UyqidiOiw');
    }
    
    console.log('✅ База данных успешно инициализирована');
    
  } catch (error) {
    console.error('❌ Ошибка инициализации базы данных:', error);
    throw error;
  } finally {
    client.release();
  }
}

async function closePool() {
  await pool.end();
}

// Если файл запущен напрямую
if (require.main === module) {
  initDatabase()
    .then(() => {
      console.log('🎉 Инициализация завершена');
      return closePool();
    })
    .catch((error) => {
      console.error('💥 Критическая ошибка:', error);
      process.exit(1);
    });
}

module.exports = { pool, initDatabase, closePool };
