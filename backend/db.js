const mysql = require('mysql2/promise');
require('dotenv').config();

const host = process.env.DB_HOST || 'localhost';
const user = process.env.DB_USER || 'root';
const password = process.env.DB_PASSWORD || '';
const database = process.env.DB_NAME || 'qradar_audit_db';

let pool = null;
let isUsingMockDB = false;

// In-Memory fallback store
const mockDB = {
  users: [
    { id: 1, username: 'admin', password: 'admin123', role: 'ADMIN' },
    { id: 2, username: 'user', password: 'user123', role: 'USER' }
  ],
  log_activity: [
    {
      id: 1,
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' '),
      username: 'admin',
      ip_address: '192.168.1.12',
      device_name: 'Windows 11 Client',
      location: 'Local Network',
      status: 'SUCCESS',
      details: 'Administrator dashboard initialized successfully.'
    },
    {
      id: 2,
      timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' '),
      username: 'root',
      ip_address: '198.51.100.5',
      device_name: 'Linux OS Daemon',
      location: 'Beijing, China',
      status: 'FAILED',
      details: 'Invalid credential attempt (User root).'
    },
    {
      id: 3,
      timestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' '),
      username: 'admin',
      ip_address: '198.51.100.5',
      device_name: 'Linux OS Daemon',
      location: 'Beijing, China',
      status: 'FAILED',
      details: 'Invalid credential attempt (User admin).'
    },
    {
      id: 4,
      timestamp: new Date(Date.now() - 7 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' '),
      username: 'administrator',
      ip_address: '198.51.100.5',
      device_name: 'Linux OS Daemon',
      location: 'Beijing, China',
      status: 'FAILED',
      details: 'Invalid credential attempt (User administrator). (Failed Attempt #3)'
    }
  ],
  offenses: [
    {
      id: 101,
      source_ip: '198.51.100.5',
      offense_type: 'Multiple Login Failures Rule Triggered',
      severity: 'HIGH',
      failed_attempts: 3,
      status: 'BLOCKED',
      last_detected: new Date(Date.now() - 7 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ')
    }
  ],
  security_rules: [
    { rule_key: 'max_failed_logins', rule_value: 3 },
    { rule_key: 'max_deposit_limit', rule_value: 100000 },
    { rule_key: 'max_transfer_limit', rule_value: 50000 },
    { rule_key: 'max_loan_limit', rule_value: 500000 },
    { rule_key: 'max_daily_deposit_limit', rule_value: 200000 },
    { rule_key: 'max_daily_transfer_limit', rule_value: 100000 },
    { rule_key: 'max_daily_loan_limit', rule_value: 1000000 }
  ]
};

async function initDB() {
  try {
    const initConnection = await mysql.createConnection({ host, user, password });
    await initConnection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\`;`);
    await initConnection.end();

    pool = mysql.createPool({
      host,
      user,
      password,
      database,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });

    console.log(`[DATABASE] Connected to MySQL at ${host}:${database}`);

    // Create Tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'USER'
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS log_activity (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username VARCHAR(50) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        device_name VARCHAR(100) NOT NULL,
        location VARCHAR(100) NOT NULL,
        status VARCHAR(20) NOT NULL,
        details VARCHAR(255)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS offenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        source_ip VARCHAR(45) UNIQUE NOT NULL,
        offense_type VARCHAR(100) DEFAULT 'Multiple Login Failures',
        severity VARCHAR(20) DEFAULT 'HIGH',
        failed_attempts INT DEFAULT 1,
        status VARCHAR(20) DEFAULT 'BLOCKED',
        last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS security_rules (
        rule_key VARCHAR(50) PRIMARY KEY,
        rule_value INT NOT NULL
      );
    `);

    // Seed default users if empty
    const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
    if (userCount[0].count === 0) {
      await pool.query(`
        INSERT INTO users (username, password, role) VALUES 
        ('admin', 'admin123', 'ADMIN'),
        ('user', 'user123', 'USER')
      `);
      console.log('[DATABASE] Seeded default system users.');
    }

    // Seed default rules if empty
    const [ruleCount] = await pool.query('SELECT COUNT(*) as count FROM security_rules');
    if (ruleCount[0].count === 0) {
      await pool.query(`
        INSERT INTO security_rules (rule_key, rule_value) VALUES 
        ('max_failed_logins', 3),
        ('max_deposit_limit', 100000),
        ('max_transfer_limit', 50000),
        ('max_loan_limit', 500000),
        ('max_daily_deposit_limit', 200000),
        ('max_daily_transfer_limit', 100000),
        ('max_daily_loan_limit', 1000000)
      `);
      console.log('[DATABASE] Seeded default SIEM security policies.');
    }

    // Seed sample offense if empty
    const [offenseCount] = await pool.query('SELECT COUNT(*) as count FROM offenses');
    if (offenseCount[0].count === 0) {
      await pool.query(`
        INSERT INTO offenses (source_ip, offense_type, severity, failed_attempts, status) 
        VALUES ('198.51.100.5', 'Multiple Login Failures Rule Triggered', 'HIGH', 3, 'BLOCKED')
      `);
      await pool.query(`
        INSERT INTO log_activity (username, ip_address, device_name, location, status, details)
        VALUES 
        ('admin', '192.168.1.12', 'Windows 11 Client', 'Local Network', 'SUCCESS', 'Administrator dashboard initialized successfully.'),
        ('root', '198.51.100.5', 'Linux OS Daemon', 'Beijing, China', 'FAILED', 'Invalid credential attempt (User root).'),
        ('admin', '198.51.100.5', 'Linux OS Daemon', 'Beijing, China', 'FAILED', 'Invalid credential attempt (User admin).'),
        ('administrator', '198.51.100.5', 'Linux OS Daemon', 'Beijing, China', 'FAILED', 'Invalid credential attempt (User administrator). (Failed Attempt #3)')
      `);
      console.log('[DATABASE] Seeded initial sample security logs.');
    }

  } catch (error) {
    isUsingMockDB = true;
    console.warn('================================================================');
    console.warn('[DATABASE WARNING] Failed to connect to local MySQL server.');
    console.warn(`Error: ${error.message}`);
    console.warn('FALLING BACK TO LOCAL IN-MEMORY DATABASE.');
    console.warn('================================================================');
  }
}

initDB();

module.exports = {
  query: async (sql, params = []) => {
    if (isUsingMockDB) {
      return runMockQuery(sql, params);
    }
    return pool.query(sql, params);
  },
  isMock: () => isUsingMockDB
};

// Mock SQL Query Parser
function runMockQuery(sql, params) {
  const normalizedSql = sql.trim().replace(/\s+/g, ' ').toUpperCase();

  // 1. SELECT USERS (Excluding password)
  if (normalizedSql.startsWith('SELECT ID, USERNAME, ROLE FROM USERS') || normalizedSql.startsWith('SELECT * FROM USERS')) {
    const list = mockDB.users.map(u => ({ id: u.id, username: u.username, role: u.role }));
    return [list];
  }

  // 2. QUERY PASSWORD AND ROLE FOR AUTH CHECK
  if (normalizedSql.includes('SELECT PASSWORD, ROLE FROM USERS WHERE USERNAME = ?')) {
    const user = params[0];
    const match = mockDB.users.find(u => u.username.toLowerCase() === user.toLowerCase());
    return [match ? [match] : []];
  }

  // 3. SELECT LOGS
  if (normalizedSql.startsWith('SELECT * FROM LOG_ACTIVITY')) {
    const result = [...mockDB.log_activity].reverse();
    return [result];
  }

  // 4. SELECT OFFENSES
  if (normalizedSql.startsWith('SELECT * FROM OFFENSES')) {
    return [mockDB.offenses];
  }

  // 5. SELECT SECURITY RULES
  if (normalizedSql.startsWith('SELECT * FROM SECURITY_RULES')) {
    return [mockDB.security_rules];
  }

  // 6. CHECK IF IP IS BLOCKED
  if (normalizedSql.includes('FROM OFFENSES WHERE SOURCE_IP = ? AND STATUS = \'BLOCKED\'')) {
    const ip = params[0];
    const match = mockDB.offenses.find(o => o.source_ip === ip && o.status === 'BLOCKED');
    return [match ? [match] : []];
  }

  // 7. SELECT SINGLE OFFENSE
  if (normalizedSql.includes('SELECT FAILED_ATTEMPTS FROM OFFENSES WHERE SOURCE_IP = ?')) {
    const ip = params[0];
    const match = mockDB.offenses.find(o => o.source_ip === ip);
    return [match ? [match] : []];
  }

  // 8. INSERT LOG ACTIVITY
  if (normalizedSql.startsWith('INSERT INTO LOG_ACTIVITY')) {
    const newLog = {
      id: mockDB.log_activity.length + 1,
      timestamp: new Date().toISOString().slice(0, 19).replace('T', ' '),
      username: params[0],
      ip_address: params[1],
      device_name: params[2],
      location: params[3],
      status: params[4],
      details: params[5]
    };
    mockDB.log_activity.push(newLog);
    return [{ insertId: newLog.id }];
  }

  // 9. INSERT OFFENSE
  if (normalizedSql.startsWith('INSERT INTO OFFENSES (SOURCE_IP, FAILED_ATTEMPTS, STATUS)')) {
    const newOffense = {
      id: mockDB.offenses.length + 101,
      source_ip: params[0],
      offense_type: 'Multiple Login Failures Rule Triggered',
      severity: 'HIGH',
      failed_attempts: params[1] || 1,
      status: params[2] || 'BLOCKED',
      last_detected: new Date().toISOString().slice(0, 19).replace('T', ' ')
    };
    mockDB.offenses.push(newOffense);
    return [{ insertId: newOffense.id }];
  }

  // 10. INSERT OR UPDATE OFFENSE FOR BANK LIMIT BREACH (CUSTOM TYPE)
  if (normalizedSql.startsWith('INSERT INTO OFFENSES (SOURCE_IP, OFFENSE_TYPE, SEVERITY, FAILED_ATTEMPTS, STATUS)')) {
    mockDB.offenses = mockDB.offenses.filter(o => o.source_ip !== params[0]);
    const newOffense = {
      id: mockDB.offenses.length + 101,
      source_ip: params[0],
      offense_type: params[1],
      severity: params[2],
      failed_attempts: params[3] || 1,
      status: params[4] || 'BLOCKED',
      last_detected: new Date().toISOString().slice(0, 19).replace('T', ' ')
    };
    mockDB.offenses.push(newOffense);
    return [{ insertId: newOffense.id }];
  }

  // 11. UPDATE OFFENSE FAIL COUNTS
  if (normalizedSql.startsWith('UPDATE OFFENSES SET FAILED_ATTEMPTS = ?, STATUS = \'BLOCKED\'')) {
    const attempts = params[0];
    const ip = params[1];
    const match = mockDB.offenses.find(o => o.source_ip === ip);
    if (match) {
      match.failed_attempts = attempts;
      match.status = 'BLOCKED';
      match.last_detected = new Date().toISOString().slice(0, 19).replace('T', ' ');
    }
    return [{ affectedRows: match ? 1 : 0 }];
  }

  // 12. UNBLOCK IP
  if (normalizedSql.startsWith('UPDATE OFFENSES SET STATUS = \'UNBLOCKED\', FAILED_ATTEMPTS = 0')) {
    const ip = params[0];
    const match = mockDB.offenses.find(o => o.source_ip === ip);
    if (match) {
      match.status = 'UNBLOCKED';
      match.failed_attempts = 0;
      match.last_detected = new Date().toISOString().slice(0, 19).replace('T', ' ');
    }
    return [{ affectedRows: match ? 1 : 0 }];
  }

  // 13. UPDATE SECURITY RULE
  if (normalizedSql.startsWith('UPDATE SECURITY_RULES SET RULE_VALUE = ? WHERE RULE_KEY = ?') ||
      normalizedSql.startsWith('INSERT INTO SECURITY_RULES (RULE_KEY, RULE_VALUE)')) {
    const targetKey = sql.includes('WHERE') ? params[1] : params[0];
    const targetVal = sql.includes('WHERE') ? params[0] : params[1];
    
    const rule = mockDB.security_rules.find(r => r.rule_key === targetKey);
    if (rule) {
      rule.rule_value = parseInt(targetVal);
    } else {
      mockDB.security_rules.push({ rule_key: targetKey, rule_value: parseInt(targetVal) });
    }
    return [{ affectedRows: 1 }];
  }

  // 14. REGISTER NEW USER (ADMIN CONSOLE)
  if (normalizedSql.startsWith('INSERT INTO USERS (USERNAME, PASSWORD, ROLE)')) {
    // Check if user exists first
    const u = params[0];
    const match = mockDB.users.find(x => x.username.toLowerCase() === u.toLowerCase());
    if (match) {
      const err = new Error("ER_DUP_ENTRY: Duplicate entry");
      err.code = "ER_DUP_ENTRY";
      throw err;
    }
    const newUser = {
      id: mockDB.users.length + 1,
      username: params[0],
      password: params[1],
      role: params[2]
    };
    mockDB.users.push(newUser);
    return [{ insertId: newUser.id }];
  }

  // 15. RESET USER PASSWORD (PUBLIC FORGOT PASSWORD)
  if (normalizedSql.startsWith('UPDATE USERS SET PASSWORD = ? WHERE USERNAME = ?')) {
    const pwd = params[0];
    const u = params[1];
    const match = mockDB.users.find(x => x.username.toLowerCase() === u.toLowerCase());
    if (match) {
      match.password = pwd;
    }
    return [{ affectedRows: match ? 1 : 0 }];
  }

  return [[]];
}
