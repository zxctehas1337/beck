const { pool } = require('./db/init');

class User {
  static async findOne(query) {
    const client = await pool.connect();
    try {
      let sql = 'SELECT * FROM users WHERE ';
      const values = [];
      let paramCount = 1;
      
      if (query.usernameLower) {
        sql += `username_lower = $${paramCount}`;
        values.push(query.usernameLower);
      } else if (query._id) {
        sql += `id = $${paramCount}`;
        values.push(query._id);
      }
      
      const result = await client.query(sql, values);
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }
  
  static async findById(id) {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }
  
  static async find(query = {}, projection = {}) {
    const client = await pool.connect();
    try {
      let sql = 'SELECT * FROM users';
      const values = [];
      let paramCount = 1;
      
      if (Object.keys(query).length > 0) {
        sql += ' WHERE ';
        const conditions = [];
        
        if (query.usernameLower && query.usernameLower.$ne) {
          conditions.push(`username_lower != $${paramCount}`);
          values.push(query.usernameLower.$ne);
          paramCount++;
        }
        
        if (conditions.length > 0) {
          sql += conditions.join(' AND ');
        }
      }
      
      if (projection.username !== undefined || projection.createdAt !== undefined) {
        sql = sql.replace('SELECT *', 'SELECT id, username, created_at');
      }
      
      sql += ' ORDER BY created_at DESC';
      
      const result = await client.query(sql, values);
      return result.rows;
    } finally {
      client.release();
    }
  }
  
  static async create(userData) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO users (username, username_lower, password_hash, is_admin, is_blocked, block_reason, last_login_at, login_count)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      `, [
        userData.username,
        userData.usernameLower,
        userData.passwordHash,
        userData.isAdmin || false,
        userData.isBlocked || false,
        userData.blockReason || '',
        userData.lastLoginAt || null,
        userData.loginCount || 0
      ]);
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }
  
  static async deleteMany(query) {
    const client = await pool.connect();
    try {
      let sql = 'DELETE FROM users WHERE ';
      const values = [];
      let paramCount = 1;
      
      if (query.usernameLower && query.usernameLower.$ne) {
        sql += `username_lower != $${paramCount}`;
        values.push(query.usernameLower.$ne);
      }
      
      const result = await client.query(sql, values);
      return { deletedCount: result.rowCount };
    } finally {
      client.release();
    }
  }
  
  static async findByIdAndDelete(id) {
    const client = await pool.connect();
    try {
      const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
      return result.rows[0] || null;
    } finally {
      client.release();
    }
  }
  
  // Метод для обновления пользователя (аналог save() в Mongoose)
  async save() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        UPDATE users 
        SET username = $1, username_lower = $2, password_hash = $3, is_admin = $4, 
            is_blocked = $5, block_reason = $6, last_login_at = $7, login_count = $8
        WHERE id = $9
        RETURNING *
      `, [
        this.username,
        this.username_lower,
        this.password_hash,
        this.is_admin,
        this.is_blocked,
        this.block_reason,
        this.last_login_at,
        this.login_count,
        this.id
      ]);
      
      // Обновляем текущий объект
      Object.assign(this, result.rows[0]);
      return this;
    } finally {
      client.release();
    }
  }
}

module.exports = User;



