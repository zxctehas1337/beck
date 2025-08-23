const { pool } = require('./db/init');

class File {
  static async create(fileData) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO files (message_id, file_name, file_type, file_size, file_url, thumbnail_url)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, [
        fileData.messageId,
        fileData.fileName,
        fileData.fileType,
        fileData.fileSize,
        fileData.fileUrl,
        fileData.thumbnailUrl || null
      ]);
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }
  
  static async findByMessageId(messageId) {
    const client = await pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM files WHERE message_id = $1 ORDER BY created_at ASC',
        [messageId]
      );
      return result.rows;
    } finally {
      client.release();
    }
  }
  
  static async findById(id) {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM files WHERE id = $1', [id]);
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }
  
  static async deleteById(id) {
    const client = await pool.connect();
    try {
      const result = await client.query('DELETE FROM files WHERE id = $1 RETURNING *', [id]);
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }
  
  static async getFileStats() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          COUNT(*) as total_files,
          SUM(file_size) as total_size,
          AVG(file_size) as avg_size,
          MIN(uploaded_at) as oldest_file,
          MAX(uploaded_at) as newest_file
        FROM files
      `);
      return result.rows[0];
    } finally {
      client.release();
    }
  }
}

module.exports = File;
