const { pool } = require('./db/init');
const File = require('./File');

class Message {
  static async find(query = {}) {
    const client = await pool.connect();
    try {
      let sql = 'SELECT * FROM messages';
      const values = [];
      let paramCount = 1;
      
      if (query.chatId) {
        sql += ' WHERE chat_id = $1';
        values.push(query.chatId);
      }
      
      sql += ' ORDER BY timestamp ASC';
      
      const result = await client.query(sql, values);
      
      // Загружаем файлы для каждого сообщения
      const messagesWithFiles = await Promise.all(
        result.rows.map(async (message) => {
          const files = await File.findByMessageId(message.id);
          return { ...message, files };
        })
      );
      
      return messagesWithFiles;
    } finally {
      client.release();
    }
  }
  
  static async create(messageData) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO messages (username, text, chat_id, timestamp)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [
        messageData.username,
        messageData.text,
        messageData.chatId,
        messageData.timestamp || new Date()
      ]);
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }
}

module.exports = Message;


