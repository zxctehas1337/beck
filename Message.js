const { pool } = require('./db/init');

class Message {
  static async find(query = {}) {
    const client = await pool.connect();
    try {
      let sql = `
        SELECT 
          m.*,
          r.username as reply_username,
          r.text as reply_text,
          r.timestamp as reply_timestamp
        FROM messages m
        LEFT JOIN messages r ON m.reply_to = r.id
      `;
      const values = [];
      let paramCount = 1;
      
      if (query.chatId) {
        sql += ' WHERE m.chat_id = $1';
        values.push(query.chatId);
      }
      
      sql += ' ORDER BY m.timestamp ASC';
      
      const result = await client.query(sql, values);
      
      // Форматируем результат для включения информации об ответах
      return result.rows.map(row => ({
        id: row.id,
        username: row.username,
        text: row.text,
        chatId: row.chat_id,
        timestamp: row.timestamp,
        replyTo: row.reply_to ? {
          id: row.reply_to,
          username: row.reply_username,
          text: row.reply_text,
          timestamp: row.reply_timestamp
        } : null
      }));
    } catch (error) {
      console.error('❌ Error in Message.find:', error);
      return [];
    } finally {
      client.release();
    }
  }
  
  static async create(messageData) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO messages (username, text, chat_id, timestamp, reply_to)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [
        messageData.username,
        messageData.text,
        messageData.chatId,
        messageData.timestamp || new Date(),
        messageData.replyTo || null
      ]);
      
      // Получаем полную информацию о сообщении включая ответ
      const fullMessage = await client.query(`
        SELECT 
          m.*,
          r.username as reply_username,
          r.text as reply_text,
          r.timestamp as reply_timestamp
        FROM messages m
        LEFT JOIN messages r ON m.reply_to = r.id
        WHERE m.id = $1
      `, [result.rows[0].id]);
      
      const row = fullMessage.rows[0];
      return {
        id: row.id,
        username: row.username,
        text: row.text,
        chatId: row.chat_id,
        timestamp: row.timestamp,
        replyTo: row.reply_to ? {
          id: row.reply_to,
          username: row.reply_username,
          text: row.reply_text,
          timestamp: row.reply_timestamp
        } : null
      };
    } catch (error) {
      console.error('❌ Error in Message.create:', error);
      throw error;
    } finally {
      client.release();
    }
  }
  
  static async findById(id) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          m.*,
          r.username as reply_username,
          r.text as reply_text,
          r.timestamp as reply_timestamp
        FROM messages m
        LEFT JOIN messages r ON m.reply_to = r.id
        WHERE m.id = $1
      `, [id]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const row = result.rows[0];
      return {
        id: row.id,
        username: row.username,
        text: row.text,
        chatId: row.chat_id,
        timestamp: row.timestamp,
        replyTo: row.reply_to ? {
          id: row.reply_to,
          username: row.reply_username,
          text: row.reply_text,
          timestamp: row.reply_timestamp
        } : null
      };
    } catch (error) {
      console.error('❌ Error in Message.findById:', error);
      return null;
    } finally {
      client.release();
    }
  }
}

module.exports = Message;


