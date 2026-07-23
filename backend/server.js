const express = require('express');
const cors = require('cors');
const db = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Track temporary local failure counts if database fails or in-memory operations are needed
const localFailures = new Map();

// Helper to parse OS/Device Name from User-Agent if not simulated
function getDeviceFromUA(userAgent = '') {
  if (userAgent.includes('Windows')) return 'Windows PC';
  if (userAgent.includes('Macintosh')) return 'MacBook / Mac OS';
  if (userAgent.includes('Linux')) return 'Linux System';
  if (userAgent.includes('Android')) return 'Android Device';
  if (userAgent.includes('iPhone') || userAgent.includes('iPad')) return 'iOS Device';
  return 'Generic Web Browser';
}

// Helper to get client IP dynamically
function getClientIP(req) {
  let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  if (ip === '::1' || ip === '::ffff:127.0.0.1') {
    ip = '127.0.0.1';
  }
  return ip;
}

/**
 * Helper to fetch and format security rules from the database
 */
async function getSecurityRules() {
  const defaultRules = {
    maxFailedLogins: 3,
    maxDepositLimit: 100000,
    maxTransferLimit: 50000,
    maxLoanLimit: 500000,
    maxDailyDepositLimit: 200000,
    maxDailyTransferLimit: 100000,
    maxDailyLoanLimit: 1000000
  };
  
  try {
    const [rows] = await db.query("SELECT * FROM security_rules");
    if (rows && rows.length > 0) {
      const rules = {};
      rows.forEach(r => {
        if (r.rule_key === 'max_failed_logins') rules.maxFailedLogins = r.rule_value;
        if (r.rule_key === 'max_deposit_limit') rules.maxDepositLimit = r.rule_value;
        if (r.rule_key === 'max_transfer_limit') rules.maxTransferLimit = r.rule_value;
        if (r.rule_key === 'max_loan_limit') rules.maxLoanLimit = r.rule_value;
        if (r.rule_key === 'max_daily_deposit_limit') rules.maxDailyDepositLimit = r.rule_value;
        if (r.rule_key === 'max_daily_transfer_limit') rules.maxDailyTransferLimit = r.rule_value;
        if (r.rule_key === 'max_daily_loan_limit') rules.maxDailyLoanLimit = r.rule_value;
      });
      return { ...defaultRules, ...rules };
    }
  } catch (err) {
    console.error("Error reading database rules, using defaults: ", err.message);
  }
  return defaultRules;
}

/**
 * Helper to calculate cumulative transactions sum for a user on the current day
 */
async function getDailyCumulativeSum(username, actionType) {
  try {
    const [logs] = await db.query(
      "SELECT timestamp, details FROM log_activity WHERE username = ? AND status = 'SUCCESS'",
      [username]
    );

    const todayStr = new Date().toISOString().slice(0, 10);
    
    let totalSum = 0;
    logs.forEach(log => {
      let logDate = '';
      if (log.timestamp instanceof Date) {
        logDate = log.timestamp.toISOString().slice(0, 10);
      } else {
        logDate = String(log.timestamp).slice(0, 10);
      }

      if (logDate === todayStr && log.details && log.details.startsWith(`Bank Action: ${actionType}`)) {
        const match = log.details.match(/Amount: ₹([\d.]+)/);
        if (match) {
          totalSum += parseFloat(match[1]);
        }
      }
    });

    return totalSum;
  } catch (err) {
    console.error("Error calculating daily cumulative sum: ", err);
    return 0;
  }
}

/**
 * Endpoint to GET active correlation rules
 */
app.get('/api/rules', async (req, res) => {
  const rules = await getSecurityRules();
  res.json({ success: true, rules });
});

/**
 * Endpoint to POST/UPDATE active correlation rules
 */
app.post('/api/rules', async (req, res) => {
  const { 
    maxFailedLogins, 
    maxDepositLimit, 
    maxTransferLimit, 
    maxLoanLimit,
    maxDailyDepositLimit,
    maxDailyTransferLimit,
    maxDailyLoanLimit
  } = req.body;
  
  const clientIP = getClientIP(req);
  const deviceName = getDeviceFromUA(req.headers['user-agent']);

  try {
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_failed_logins'", [maxFailedLogins]);
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_deposit_limit'", [maxDepositLimit]);
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_transfer_limit'", [maxTransferLimit]);
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_loan_limit'", [maxLoanLimit]);
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_daily_deposit_limit'", [maxDailyDepositLimit]);
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_daily_transfer_limit'", [maxDailyTransferLimit]);
    await db.query("UPDATE security_rules SET rule_value = ? WHERE rule_key = 'max_daily_loan_limit'", [maxDailyLoanLimit]);

    await db.query(
      "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES ('admin', ?, ?, 'Localhost', 'SUCCESS', ?)",
      [clientIP, deviceName, "Administrator modified SIEM correlation policy limits (single & daily cumulative thresholds)."]
    );

    res.json({ success: true, message: 'SIEM rules updated successfully.' });
  } catch (error) {
    console.error('Error saving rules: ', error);
    res.status(500).json({ success: false, message: 'Failed to save correlation rules.' });
  }
});

/**
 * Endpoint to GET registered users list (Admin Console)
 */
app.get('/api/users', async (req, res) => {
  try {
    const [users] = await db.query("SELECT id, username, role FROM users");
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error retrieving user list.' });
  }
});

/**
 * Endpoint to POST/REGISTER new user (Admin Console restricted)
 */
app.post('/api/users', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  }

  const clientIP = getClientIP(req);
  const deviceName = getDeviceFromUA(req.headers['user-agent']);

  try {
    await db.query(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
      [username, password, role]
    );

    // Audit log
    await db.query(
      "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES ('admin', ?, ?, 'Localhost', 'SUCCESS', ?)",
      [clientIP, deviceName, `Administrator created new user profile: "${username}" with authorization: "${role}"`]
    );

    res.json({ success: true, message: `Account created successfully for ${username}.` });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Username already exists.' });
    }
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to create user account.' });
  }
});

/**
 * Endpoint to POST/RESET password (Public Forgot Password Flow)
 */
app.post('/api/users/reset', async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required.' });
  }

  const clientIP = getClientIP(req);
  const deviceName = getDeviceFromUA(req.headers['user-agent']);

  try {
    // Check if user exists first
    const [userRecords] = await db.query("SELECT role FROM users WHERE username = ?", [username]);
    if (!userRecords || userRecords.length === 0) {
      return res.status(404).json({ success: false, message: 'Username not found in system records.' });
    }

    // Update password
    await db.query(
      "UPDATE users SET password = ? WHERE username = ?",
      [newPassword, username]
    );

    // Audit log
    await db.query(
      "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, 'Localhost', 'SUCCESS', ?)",
      [username, clientIP, deviceName, `User successfully reset their password.`]
    );

    res.json({ success: true, message: 'Password reset successfully completed.' });
  } catch (err) {
    console.error("Error resetting password: ", err);
    res.status(500).json({ success: false, message: 'Database error resetting password.' });
  }
});

/**
 * 1. Base Authentication & Logging Endpoint
 */
app.post('/api/login', async (req, res) => {
  const { username, password, simulatedIP, simulatedDevice, simulatedLocation } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  const clientIP = simulatedIP || getClientIP(req);
  const deviceName = simulatedDevice || getDeviceFromUA(req.headers['user-agent']);
  const location = simulatedLocation || 'Local Network';
  
  try {
    const rules = await getSecurityRules();

    // --- RULE 1: Check if IP is currently blocked ---
    const [blockedRecords] = await db.query(
      "SELECT status FROM offenses WHERE source_ip = ? AND status = 'BLOCKED'", 
      [clientIP]
    );

    if (blockedRecords && blockedRecords.length > 0) {
      await db.query(
        "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, 'FAILED', ?)",
        [username, clientIP, deviceName, location, "BLOCKED IP ACCESS ATTEMPT: Blacklisted source IP tried to authenticate."]
      );
      
      return res.status(403).json({ 
        success: false, 
        message: `Access Denied! Your IP [${clientIP}] is blacklisted due to security policy violations.` 
      });
    }

    // --- RULE 2: Validate Credentials against MySQL database ---
    const [userRecords] = await db.query(
      "SELECT password, role FROM users WHERE username = ?",
      [username]
    );

    let isSuccess = false;
    let role = 'USER';
    
    if (userRecords && userRecords.length > 0) {
      const dbPassword = userRecords[0].password;
      const dbRole = userRecords[0].role;
      
      if (dbPassword === password) {
        isSuccess = true;
        role = dbRole;
      }
    }
    
    const status = isSuccess ? 'SUCCESS' : 'FAILED';
    let details = isSuccess 
      ? `${role === 'ADMIN' ? 'Administrator' : 'User'} session established successfully.`
      : 'Invalid password credential attempt.';

    if (isSuccess) {
      // Reset failed count on success
      await db.query("UPDATE offenses SET failed_attempts = 0, status = 'UNBLOCKED' WHERE source_ip = ?", [clientIP]);
      localFailures.set(clientIP, 0);

      await db.query(
        "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, ?, ?)",
        [username, clientIP, deviceName, location, status, details]
      );

      return res.json({ 
        success: true, 
        role: role, 
        message: 'Login successful!' 
      });
    } else {
      // Increment failures
      const [rows] = await db.query("SELECT failed_attempts FROM offenses WHERE source_ip = ?", [clientIP]);
      let attempts = 0;
      if (rows && rows.length > 0) {
        attempts = rows[0].failed_attempts;
      }
      attempts++;

      details += ` (Failed Attempt #${attempts})`;
      await db.query(
        "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, ?, ?)",
        [username, clientIP, deviceName, location, status, details]
      );

      // --- RULE 3: Threshold Rule (Compare with dynamic rule limit) ---
      if (attempts >= rules.maxFailedLogins) {
        if (rows && rows.length > 0) {
          await db.query(
            "UPDATE offenses SET failed_attempts = ?, status = 'BLOCKED' WHERE source_ip = ?",
            [attempts, clientIP]
          );
        } else {
          await db.query(
            "INSERT INTO offenses (source_ip, failed_attempts, status) VALUES (?, ?, 'BLOCKED')",
            [clientIP, attempts]
          );
        }

        return res.status(401).json({
          success: false,
          message: `Login failed. Threshold breached! IP [${clientIP}] has been dynamically BLOCKED.`,
          attempts
        });
      } else {
        if (rows && rows.length > 0) {
          await db.query("UPDATE offenses SET failed_attempts = ? WHERE source_ip = ?", [attempts, clientIP]);
        } else {
          await db.query("INSERT INTO offenses (source_ip, failed_attempts, status) VALUES (?, ?, 'UNBLOCKED')", [clientIP, attempts]);
        }

        return res.status(401).json({
          success: false,
          message: `Invalid credentials. Attempt ${attempts}/${rules.maxFailedLogins} for IP: ${clientIP}`,
          attempts
        });
      }
    }
  } catch (error) {
    console.error('Server error during auth: ', error);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

/**
 * 2. Session Logout Endpoint
 */
app.post('/api/logout', async (req, res) => {
  const { username, simulatedIP, simulatedDevice, simulatedLocation, durationSeconds } = req.body;

  const clientIP = simulatedIP || getClientIP(req);
  const deviceName = simulatedDevice || getDeviceFromUA(req.headers['user-agent']);
  const location = simulatedLocation || 'Local Network';

  try {
    const details = `User session closed. Session active duration: ${durationSeconds} seconds.`;
    
    await db.query(
      "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, 'SUCCESS', ?)",
      [username, clientIP, deviceName, location, details]
    );

    res.json({ success: true, message: 'Logout logged successfully.' });
  } catch (error) {
    console.error('Error logging logout: ', error);
    res.status(500).json({ success: false, message: 'Database logging error.' });
  }
});

/**
 * 3. Auditing Banking Transactions & Enforcing Policy Thresholds
 */
app.post('/api/bank/action', async (req, res) => {
  const { username, simulatedIP, simulatedDevice, simulatedLocation, actionType, amount, purpose } = req.body;

  const clientIP = simulatedIP || getClientIP(req);
  const deviceName = simulatedDevice || getDeviceFromUA(req.headers['user-agent']);
  const location = simulatedLocation || 'Local Network';
  const amt = parseFloat(amount);

  try {
    const rules = await getSecurityRules();
    
    let isSingleBreached = false;
    let singleLimitValue = 0;
    let singleRuleName = "";

    let isDailyBreached = false;
    let dailyLimitValue = 0;
    let dailyRuleName = "";

    if (actionType === 'DEPOSIT') {
      isSingleBreached = amt > rules.maxDepositLimit;
      singleLimitValue = rules.maxDepositLimit;
      singleRuleName = "Single Deposit Limit Breached";

      dailyLimitValue = rules.maxDailyDepositLimit;
      dailyRuleName = "Daily Cumulative Deposit Limit Breached";
    } else if (actionType === 'TRANSFER') {
      isSingleBreached = amt > rules.maxTransferLimit;
      singleLimitValue = rules.maxTransferLimit;
      singleRuleName = "Single Transfer Limit Breached";

      dailyLimitValue = rules.maxDailyTransferLimit;
      dailyRuleName = "Daily Cumulative Transfer Limit Breached";
    } else if (actionType === 'LOAN') {
      isSingleBreached = amt > rules.maxLoanLimit;
      singleLimitValue = rules.maxLoanLimit;
      singleRuleName = "Single Loan Limit Breached";

      dailyLimitValue = rules.maxDailyLoanLimit;
      dailyRuleName = "Daily Cumulative Loan Limit Breached";
    }

    if (isSingleBreached) {
      const breachSummary = `ANOMALY BLOCKED: Bank ${actionType} breached single-transaction limit. Amount: ₹${amt.toFixed(2)} (Limit: ₹${singleLimitValue.toFixed(2)}) | Purpose: "${purpose}"`;
      
      await db.query(
        "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, 'FAILED', ?)",
        [username, clientIP, deviceName, location, breachSummary]
      );

      // Fixed: Use ON DUPLICATE KEY UPDATE to prevent ER_DUP_ENTRY errors in MySQL
      await db.query(
        "INSERT INTO offenses (source_ip, offense_type, severity, failed_attempts, status) VALUES (?, ?, 'HIGH', 1, 'BLOCKED') ON DUPLICATE KEY UPDATE offense_type = ?, status = 'BLOCKED', severity = 'HIGH'",
        [clientIP, singleRuleName, singleRuleName]
      );

      return res.status(403).json({
        success: false,
        message: `Security Threat Intercepted! The single transaction amount ₹${amt} exceeds the safety limit of ₹${singleLimitValue} for ${actionType} actions. Your IP has been dynamically BLOCKED.`
      });
    }

    const dailyCumulativeSum = await getDailyCumulativeSum(username, actionType);
    isDailyBreached = (dailyCumulativeSum + amt) > dailyLimitValue;

    if (isDailyBreached) {
      const cumulativeBreachSummary = `ANOMALY BLOCKED: Cumulative Daily ${actionType} limit breached. Attempted: ₹${(dailyCumulativeSum + amt).toFixed(2)} (Daily Limit: ₹${dailyLimitValue.toFixed(2)}, Past Today: ₹${dailyCumulativeSum.toFixed(2)}) | Purpose: "${purpose}"`;
      
      await db.query(
        "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, 'FAILED', ?)",
        [username, clientIP, deviceName, location, cumulativeBreachSummary]
      );

      // Fixed: Use ON DUPLICATE KEY UPDATE to prevent ER_DUP_ENTRY errors in MySQL
      await db.query(
        "INSERT INTO offenses (source_ip, offense_type, severity, failed_attempts, status) VALUES (?, ?, 'HIGH', 1, 'BLOCKED') ON DUPLICATE KEY UPDATE offense_type = ?, status = 'BLOCKED', severity = 'HIGH'",
        [clientIP, dailyRuleName, dailyRuleName]
      );

      return res.status(403).json({
        success: false,
        message: `Security Anomaly Intercepted! Your total daily transactions for ${actionType} (including this attempt) would sum to ₹${(dailyCumulativeSum + amt).toFixed(2)}, which exceeds the cumulative daily limit of ₹${dailyLimitValue}. Your IP has been dynamically BLOCKED due to suspicious structuring activity.`
      });
    }

    const transactionSummary = `Bank Action: ${actionType.toUpperCase()} | Amount: ₹${amt.toFixed(2)} | Purpose: "${purpose}"`;
    
    await db.query(
      "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES (?, ?, ?, ?, 'SUCCESS', ?)",
      [username, clientIP, deviceName, location, transactionSummary]
    );

    res.json({ success: true, message: 'Transaction audited and saved.' });
  } catch (error) {
    console.error('Error logging transaction: ', error);
    res.status(500).json({ success: false, message: 'Database logging error.' });
  }
});

/**
 * 4. Get Log Activity Logs
 */
app.get('/api/logs', async (req, res) => {
  try {
    const [logs] = await db.query("SELECT * FROM log_activity ORDER BY timestamp DESC");
    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error retrieving logs.' });
  }
});

/**
 * 5. Get Security Offenses
 */
app.get('/api/offenses', async (req, res) => {
  try {
    const [offenses] = await db.query("SELECT * FROM offenses ORDER BY last_detected DESC");
    res.json({ success: true, offenses });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error retrieving offenses.' });
  }
});

/**
 * 6. Unblock Blocked IP Address
 */
app.post('/api/unblock', async (req, res) => {
  const { ipAddress } = req.body;

  if (!ipAddress) {
    return res.status(400).json({ success: false, message: 'IP Address is required to unblock.' });
  }

  const clientIP = getClientIP(req);
  const deviceName = getDeviceFromUA(req.headers['user-agent']);

  try {
    await db.query(
      "UPDATE offenses SET status = 'UNBLOCKED', failed_attempts = 0 WHERE source_ip = ?", 
      [ipAddress]
    );

    await db.query(
      "INSERT INTO log_activity (username, ip_address, device_name, location, status, details) VALUES ('admin', ?, ?, 'Localhost', 'SUCCESS', ?)",
      [clientIP, deviceName, `Administrator manually unblocked IP: ${ipAddress}`]
    );

    res.json({ success: true, message: `Successfully unblocked IP address ${ipAddress}.` });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Database error unblocking IP.' });
  }
});

/**
 * 7. Export Logs to CSV File (Excel format)
 */
app.get('/api/export', async (req, res) => {
  try {
    const [logs] = await db.query("SELECT * FROM log_activity ORDER BY timestamp DESC");
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=qradar_security_logs.csv');

    let csvContent = 'ID,Timestamp,Username,IP Address,Device/OS,Location,Status,Details\n';
    
    for (const log of logs) {
      const escapedDetails = (log.details || '').replace(/"/g, '""');
      const escapedDevice = (log.device_name || '').replace(/"/g, '""');
      const escapedLocation = (log.location || '').replace(/"/g, '""');
      
      csvContent += `${log.id},"${log.timestamp}","${log.username}","${log.ip_address}","${escapedDevice}","${escapedLocation}","${log.status}","${escapedDetails}"\n`;
    }

    res.status(200).send(csvContent);

  } catch (error) {
    res.status(500).send('Error generating export file.');
  }
});

// App Startup
app.listen(PORT, () => {
  console.log(`[SERVER] Express Server is running on port ${PORT}`);
});
