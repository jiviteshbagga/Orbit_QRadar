import React, { useState, useEffect } from 'react';
import './App.css';

const API_BASE = 'https://orbit-siem-backend.onrender.com/api';

function App() {
  // Check URL parameter to see if we are in Admin Console Mode or Bank Customer Mode
  const [isAdminConsoleMode, setIsAdminConsoleMode] = useState(false);

  // Telemetry state scanned automatically (live public IPv4/IPv6)
  const [scannedIP, setScannedIP] = useState('127.0.0.1');
  const [scannedDevice, setScannedDevice] = useState('Generic Client');
  const [scannedLocation, setScannedLocation] = useState('Local Network');
  const [scanning, setScanning] = useState(true);

  // App Navigation States
  const [view, setView] = useState('LANDING'); // 'LANDING', 'LOGIN', 'BANK_PORTAL', 'QRADAR'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  
  // Forgot password flow states
  const [isResettingPassword, setIsResettingPassword] = useState(false);
  const [resetUsername, setResetUsername] = useState('');
  const [resetNewPassword, setResetNewPassword] = useState('');
  
  // Banking State
  const [balance, setBalance] = useState(12450.80);
  const [transactions, setTransactions] = useState([
    { id: 1, type: 'CREDIT', amount: 2500.00, purpose: 'Monthly Salary Deposit', date: '2026-07-23 10:00:00' },
    { id: 2, type: 'DEBIT', amount: 75.50, purpose: 'Coffee & Snacks', date: '2026-07-23 14:30:00' },
    { id: 3, type: 'DEBIT', amount: 1200.00, purpose: 'House Rent Payment', date: '2026-07-23 18:00:00' }
  ]);

  // Banking Forms State
  const [bankAction, setBankAction] = useState('TRANSFER'); // 'DEPOSIT', 'TRANSFER', 'LOAN'
  const [bankAmount, setBankAmount] = useState('');
  const [bankPurpose, setBankPurpose] = useState('');
  const [bankTargetAcc, setBankTargetAcc] = useState('');

  // QRadar State
  const [logs, setLogs] = useState([]);
  const [offenses, setOffenses] = useState([]);
  const [usersList, setUsersList] = useState([]);
  const [qradarTab, setQradarTab] = useState('dashboard'); // 'dashboard', 'logs', 'offenses', 'rules', 'users'
  
  // Customizable SIEM Rules State (with single & cumulative daily limits)
  const [rules, setRules] = useState({
    maxFailedLogins: 3,
    maxDepositLimit: 100000,
    maxTransferLimit: 50000,
    maxLoanLimit: 500000,
    maxDailyDepositLimit: 200000,
    maxDailyTransferLimit: 100000,
    maxDailyLoanLimit: 1000000
  });

  // User Management State (Admins Creating Users)
  const [newUserUsername, setNewUserUsername] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('USER');

  // Admin Change Password Form State
  const [changePwdUsername, setChangePwdUsername] = useState('');
  const [changePwdNewPassword, setChangePwdNewPassword] = useState('');

  // Session timer
  const [loginTime, setLoginTime] = useState(null);

  // System messages
  const [errorMsg, setErrorMsg] = useState('');

  // Check route parameter on startup
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const consoleMode = params.get('console') === 'admin';
    setIsAdminConsoleMode(consoleMode);
    
    if (consoleMode) {
      setView('LOGIN'); // Directly load the Admin login page
    } else {
      setView('LANDING'); // Load standard banking website landing page
    }
    
    autoScanTelemetry();
  }, []);

  // Poll QRadar logs if view is active
  useEffect(() => {
    if (view === 'QRADAR') {
      fetchLogs();
      fetchOffenses();
      fetchRules();
      fetchUsers();
      
      const interval = setInterval(() => {
        fetchLogs();
        fetchOffenses();
      }, 5000); // Poll every 5s

      return () => clearInterval(interval);
    }
  }, [view]);

  const autoScanTelemetry = async () => {
    setScanning(true);
    
    const ua = navigator.userAgent;
    let device = 'Generic Web Browser';
    if (ua.includes('Windows')) device = 'Windows PC';
    else if (ua.includes('Macintosh')) device = 'MacBook / Mac OS';
    else if (ua.includes('Linux')) device = 'Linux System';
    else if (ua.includes('Android')) device = 'Android Device';
    else if (ua.includes('iPhone') || ua.includes('iPad')) device = 'iOS Device';
    setScannedDevice(device);

    let finalIP = '127.0.0.1';
    let finalLoc = 'Local Network';

    try {
      const ipifyRes = await fetch('https://api64.ipify.org?format=json');
      if (ipifyRes.ok) {
        const ipifyData = await ipifyRes.json();
        if (ipifyData.ip) {
          finalIP = ipifyData.ip;
        }
      }
    } catch (e) {
      console.warn('Public IP lookup failed. Accessing from offline/private sandbox.');
    }

    if (finalIP !== '127.0.0.1') {
      try {
        const locRes = await fetch(`https://ipapi.co/${finalIP}/json/`);
        if (locRes.ok) {
          const locData = await locRes.json();
          if (locData.city) {
            finalLoc = `${locData.city}, ${locData.country_name}`;
          }
        }
      } catch (err) {
        try {
          const locRes2 = await fetch(`http://ip-api.com/json/${finalIP}`);
          if (locRes2.ok) {
            const locData2 = await locRes2.json();
            if (locData2.city) {
              finalLoc = `${locData2.city}, ${locData2.country}`;
            }
          }
        } catch (err2) {
          finalLoc = 'Unknown Location';
        }
      }
    } else {
      finalLoc = 'Local Host Loopback';
    }

    setScannedIP(finalIP);
    setScannedLocation(finalLoc);
    setScanning(false);
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');

    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          simulatedIP: scannedIP,
          simulatedDevice: scannedDevice,
          simulatedLocation: scannedLocation
        })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        // Enforce console matches role type
        if (isAdminConsoleMode && data.role !== 'ADMIN') {
          setErrorMsg('Access Denied: Standard user profiles cannot access the QRadar console.');
          return;
        }
        if (!isAdminConsoleMode && data.role === 'ADMIN') {
          setErrorMsg('Access Denied: Administrative accounts cannot log in to the user NetBanking portal.');
          return;
        }

        setLoginTime(Date.now()); // Start session timer
        
        if (data.role === 'ADMIN') {
          setView('QRADAR');
        } else {
          setView('BANK_PORTAL');
        }
      } else {
        setErrorMsg(data.message || 'Authentication failed.');
      }
    } catch (err) {
      setErrorMsg('Cannot connect to Express backend. Please ensure node server.js is running!');
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setErrorMsg('');

    if (!resetUsername.trim() || !resetNewPassword.trim()) {
      alert('Please fill out all fields.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/users/reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: resetUsername,
          newPassword: resetNewPassword
        })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        alert('Password updated successfully! You can now log in with your new password.');
        setIsResettingPassword(false);
        setResetUsername('');
        setResetNewPassword('');
      } else {
        setErrorMsg(data.message || 'Reset failed.');
      }
    } catch (err) {
      setErrorMsg('Failed to connect to reset service.');
    }
  };

  // Switch between bank flow and admin QRadar flow from landing
  const triggerQRadarLogin = () => {
    setIsAdminConsoleMode(true);
    setErrorMsg('');
    setView('LOGIN');
    setIsResettingPassword(false);
    window.history.pushState({}, '', '?console=admin');
  };

  const triggerBankLogin = () => {
    setIsAdminConsoleMode(false);
    setErrorMsg('');
    setView('LOGIN');
    setIsResettingPassword(false);
    window.history.pushState({}, '', window.location.pathname);
  };

  const triggerBackToHome = () => {
    setIsAdminConsoleMode(false);
    setErrorMsg('');
    setView('LANDING');
    setIsResettingPassword(false);
    window.history.pushState({}, '', window.location.pathname);
  };

  const handleLogout = async () => {
    const elapsedSeconds = Math.round((Date.now() - loginTime) / 1000);
    
    try {
      await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          simulatedIP: scannedIP,
          simulatedDevice: scannedDevice,
          simulatedLocation: scannedLocation,
          durationSeconds: elapsedSeconds
        })
      });
    } catch (err) {
      console.error('Error logging logout session duration:', err);
    }

    // Reset States
    if (isAdminConsoleMode) {
      setView('LOGIN'); // Redirect to Admin Login directly
    } else {
      setView('LANDING'); // Redirect to Bank homepage
      window.history.pushState({}, '', window.location.pathname);
    }
    setUsername('');
    setPassword('');
    setErrorMsg('');
    setLoginTime(null);
  };

  // Banking Transaction Actions (Deposit, Debit, Loan)
  const handleBankTransaction = async (e) => {
    e.preventDefault();
    if (!bankAmount || isNaN(bankAmount) || parseFloat(bankAmount) <= 0) {
      alert('Please enter a valid amount.');
      return;
    }
    if (!bankPurpose.trim()) {
      alert('Please specify the purpose of this transaction.');
      return;
    }

    const amt = parseFloat(bankAmount);
    let newBal = balance;
    let type = 'CREDIT';

    if (bankAction === 'TRANSFER') {
      if (amt > balance) {
        alert('Insufficient funds for this transfer.');
        return;
      }
      newBal -= amt;
      type = 'DEBIT';
    } else {
      newBal += amt;
    }

    try {
      const res = await fetch(`${API_BASE}/bank/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          simulatedIP: scannedIP,
          simulatedDevice: scannedDevice,
          simulatedLocation: scannedLocation,
          actionType: bankAction,
          amount: amt,
          purpose: bankPurpose
        })
      });
      
      const data = await res.json();
      
      if (res.ok && data.success) {
        setBalance(newBal);
        const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const detailsPurpose = bankAction === 'TRANSFER' ? `Transfer to Acc ${bankTargetAcc}: ${bankPurpose}` : bankPurpose;
        setTransactions([
          { id: transactions.length + 1, type, amount: amt, purpose: detailsPurpose, date: timestamp },
          ...transactions
        ]);

        alert('Transaction completed successfully and audited to security logs!');
        
        setBankAmount('');
        setBankPurpose('');
        setBankTargetAcc('');
      } else {
        alert(data.message || 'Transaction rejected due to security policy violations.');
        setView('LANDING');
        setUsername('');
        setPassword('');
        setLoginTime(null);
        window.history.pushState({}, '', window.location.pathname);
      }
    } catch (err) {
      alert('Audit submission failed. Check backend server.');
    }
  };

  // QRadar Management actions
  const fetchLogs = async () => {
    try {
      const res = await fetch(`${API_BASE}/logs`);
      const data = await res.json();
      if (data.success) setLogs(data.logs);
    } catch (err) {
      console.error('Error fetching logs:', err);
    }
  };

  const fetchOffenses = async () => {
    try {
      const res = await fetch(`${API_BASE}/offenses`);
      const data = await res.json();
      if (data.success) setOffenses(data.offenses);
    } catch (err) {
      console.error('Error fetching offenses:', err);
    }
  };

  const fetchRules = async () => {
    try {
      const res = await fetch(`${API_BASE}/rules`);
      const data = await res.json();
      if (data.success) {
        setRules(data.rules);
      }
    } catch (err) {
      console.error('Error fetching security rules:', err);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API_BASE}/users`);
      const data = await res.json();
      if (data.success) {
        setUsersList(data.users);
        if (data.users.length > 0 && !changePwdUsername) {
          setChangePwdUsername(data.users[0].username);
        }
      }
    } catch (err) {
      console.error('Error fetching users:', err);
    }
  };

  const handleSaveRules = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rules)
      });
      const data = await res.json();
      if (data.success) {
        alert('SIEM security policies and thresholds updated successfully!');
        fetchLogs();
      }
    } catch (err) {
      alert('Failed to save security policies. Check backend console.');
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!newUserUsername.trim() || !newUserPassword.trim()) {
      alert('Please fill out all fields.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: newUserUsername,
          password: newUserPassword,
          role: newUserRole
        })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        alert(`Account created successfully for "${newUserUsername}"!`);
        setNewUserUsername('');
        setNewUserPassword('');
        setNewUserRole('USER');
        fetchUsers();
        fetchLogs();
      } else {
        alert(data.message || 'Failed to create user account.');
      }
    } catch (err) {
      alert('Could not submit user creation request.');
    }
  };

  // Admin Change password for existing user or admin
  const handleAdminChangePassword = async (e) => {
    e.preventDefault();
    if (!changePwdUsername || !changePwdNewPassword.trim()) {
      alert('Please enter a username and new password.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/users/reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: changePwdUsername,
          newPassword: changePwdNewPassword
        })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        alert(`Password for user "${changePwdUsername}" successfully updated!`);
        setChangePwdNewPassword('');
        fetchLogs();
      } else {
        alert(data.message || 'Failed to update password.');
      }
    } catch (err) {
      alert('Error updating password.');
    }
  };

  const handleUnblock = async (ip) => {
    if (window.confirm(`Confirm unblocking and clearing records for IP: ${ip}?`)) {
      try {
        const res = await fetch(`${API_BASE}/unblock`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ipAddress: ip })
        });
        const data = await res.json();
        if (data.success) {
          alert(`IP ${ip} successfully unblocked.`);
          fetchLogs();
          fetchOffenses();
        }
      } catch (err) {
        console.error('Error unblocking:', err);
      }
    }
  };

  const handleExport = () => {
    window.open(`${API_BASE}/export`, '_blank');
  };

  // --- RENDER VIEWS ---

  // 1. Landing View (Bank Public Portal Home)
  if (view === 'LANDING') {
    return (
      <div className="landing-page">
        <header className="banking-header">
          <div className="logo">🏦 Orbit Bank</div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="login-trigger-btn" onClick={triggerBankLogin}>
              NetBanking Login
            </button>
            <button 
              className="login-trigger-btn" 
              style={{ backgroundColor: '#ef4444' }} 
              onClick={triggerQRadarLogin}
            >
              QRadar Console
            </button>
          </div>
        </header>

        <section className="hero-section">
          <h1>Secure & Reliable Online Banking</h1>
          <p>Manage your transactions, savings, and loans. Monitored and audited under SIEM protocols.</p>
          <div className="hero-buttons">
            <button className="hero-btn-primary" onClick={triggerBankLogin}>
              Login to NetBanking
            </button>
          </div>
        </section>

        <section className="features-grid">
          <div className="feature-card">
            <h3>🔒 SOC Telemetry Audited</h3>
            <p>Every transaction is monitored automatically, scanning client footprints for security.</p>
          </div>
          <div className="feature-card">
            <h3>⚡ Instant Transfers</h3>
            <p>Transfer funds instantly with zero processing latency using secure gateways.</p>
          </div>
          <div className="feature-card">
            <h3>🛡️ Security Offenses Rules</h3>
            <p>System automatically blocks IP hosts breaching login limits to prevent threats.</p>
          </div>
        </section>
      </div>
    );
  }

  // 2. Login / Reset Password View
  if (view === 'LOGIN') {
    return (
      <div className="login-page">
        {isResettingPassword ? (
          // RESET PASSWORD VIEW
          <div className="login-card">
            <div className="login-header">
              <h1>Forgot Password</h1>
              <p>Redefine account security credentials</p>
            </div>
            
            <form className="login-form" onSubmit={handleResetPassword}>
              {errorMsg && <div className="alert-box alert-error">{errorMsg}</div>}
              
              <div className="form-group">
                <label>Account Username</label>
                <input 
                  type="text"
                  placeholder="Enter your username"
                  value={resetUsername}
                  onChange={(e) => setResetUsername(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label>New Secure Password</label>
                <input 
                  type="password"
                  placeholder="Enter new password"
                  value={resetNewPassword}
                  onChange={(e) => setResetNewPassword(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="login-btn" style={{ backgroundColor: '#fbbf24', color: '#111' }}>
                Reset Password
              </button>

              <button 
                type="button"
                className="login-btn"
                style={{ marginTop: '10px', backgroundColor: '#5a646e' }}
                onClick={() => {
                  setIsResettingPassword(false);
                  setErrorMsg('');
                }}
              >
                Back to Sign In
              </button>
            </form>
          </div>
        ) : (
          // STANDARD LOGIN VIEW
          <div className="login-card">
            <div className="login-header">
              {isAdminConsoleMode ? (
                <>
                  <h1 style={{ color: '#ef4444' }}>QRadar Console Login</h1>
                  <p>Administrative Threat Management Center</p>
                </>
              ) : (
                <>
                  <h1>Orbit Bank Login</h1>
                  <p>Secure SSL Authentication Access</p>
                </>
              )}
            </div>

            <form className="login-form" onSubmit={handleLoginSubmit}>
              {errorMsg && <div className="alert-box alert-error">{errorMsg}</div>}
              
              <div className="form-group">
                <label>Username</label>
                <input 
                  type="text" 
                  value={username} 
                  onChange={(e) => setUsername(e.target.value)} 
                  placeholder={isAdminConsoleMode ? "Enter Admin Username" : "Enter Bank Username"} 
                  required 
                />
              </div>

              <div className="form-group">
                <label>Password</label>
                <input 
                  type="password" 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  placeholder="Enter password" 
                  required 
                />
              </div>

              {/* Forgot Password Link - Hidden on Admin Page, only on bank client page */}
              {!isAdminConsoleMode && (
                <div style={{ textAlign: 'right', marginBottom: '15px' }}>
                  <span 
                    className="action-link" 
                    style={{ fontSize: '12px', cursor: 'pointer', color: 'var(--accent-blue)' }}
                    onClick={() => {
                      setIsResettingPassword(true);
                      setErrorMsg('');
                    }}
                  >
                    Forgot Password?
                  </span>
                </div>
              )}

              <button type="submit" className="login-btn">
                {isAdminConsoleMode ? 'Access Console' : 'Secure Login'}
              </button>
              
              <button 
                type="button" 
                className="login-btn" 
                style={{ marginTop: '10px', backgroundColor: '#5a646e' }}
                onClick={triggerBackToHome}
              >
                Back to Home
              </button>
            </form>
          </div>
        )}
      </div>
    );
  }

  // 3. User Banking Portal View
  if (view === 'BANK_PORTAL') {
    return (
      <div className="bank-portal-container">
        <header className="portal-header">
          <div className="logo">🏦 Orbit NetBanking</div>
          <div className="user-details">
            <span>Welcome, <strong>{username}</strong> (IP: {scannedIP})</span>
            <button className="logout-btn" onClick={handleLogout} style={{ width: 'auto', padding: '6px 16px' }}>
              Logout Portal
            </button>
          </div>
        </header>

        <div className="portal-body">
          {/* Left panel: Balance and actions */}
          <div className="portal-left">
            <div className="balance-card">
              <span className="card-label">Available Balance</span>
              <h2 className="card-balance">₹{balance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</h2>
              <span className="card-no">Orbit Savings Account: **** 4892</span>
            </div>

            <div className="bank-action-card">
              <h3>Create Financial Transaction</h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                All transaction activities are audited dynamically in the QRadar log system.
              </p>

              <form onSubmit={handleBankTransaction}>
                <div className="form-group">
                  <label>Action Type</label>
                  <select value={bankAction} onChange={(e) => setBankAction(e.target.value)}>
                    <option value="TRANSFER">Transfer Funds (Debit)</option>
                    <option value="DEPOSIT">Deposit Cash (Credit)</option>
                    <option value="LOAN">Request Loan Application</option>
                  </select>
                </div>

                {bankAction === 'TRANSFER' && (
                  <div className="form-group">
                    <label>Target Account Number</label>
                    <input 
                      type="text" 
                      placeholder="e.g. 10093848" 
                      value={bankTargetAcc}
                      onChange={(e) => setBankTargetAcc(e.target.value)}
                      required
                    />
                  </div>
                )}

                <div className="form-group">
                  <label>Amount (₹)</label>
                  <input 
                    type="number" 
                    placeholder="Enter amount in ₹" 
                    value={bankAmount}
                    onChange={(e) => setBankAmount(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Transaction Purpose</label>
                  <input 
                    type="text" 
                    placeholder="e.g. Electricity Bill, Tuition Fees, Business Loan" 
                    value={bankPurpose}
                    onChange={(e) => setBankPurpose(e.target.value)}
                    required
                  />
                </div>

                <button type="submit" className="login-btn" style={{ backgroundColor: '#10b981' }}>
                  Execute Action
                </button>
              </form>
            </div>
          </div>

          {/* Right panel: transactions statement */}
          <div className="portal-right">
            <div className="statement-card">
              <h3>Real-Time Account Statement</h3>
              <div className="transaction-list">
                {transactions.map((tx) => (
                  <div className="tx-item" key={tx.id}>
                    <div className="tx-info">
                      <span className="tx-purpose">{tx.purpose}</span>
                      <span className="tx-date">{tx.date}</span>
                    </div>
                    <span className={`tx-amount ${tx.type === 'CREDIT' ? 'txt-credit' : 'txt-debit'}`}>
                      {tx.type === 'CREDIT' ? '+' : '-'}₹{tx.amount.toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 4. Admin QRadar Dashboard Console View
  // Dynamic stats calculation for Dashboard UI
  const totalLogsCount = logs.length;
  const blockedIpsCount = offenses.filter(o => o.status === 'BLOCKED').length;
  const registeredUsersCount = usersList.length;
  const failedEventsCount = logs.filter(l => l.status === 'FAILED').length;

  return (
    <div className="app-container">
      <div className="dashboard-layout">
        
        {/* Sidebar */}
        <div className="sidebar">
          <div className="sidebar-brand">
            <span style={{ color: '#ef4444', fontSize: '20px' }}>■</span>
            QRadar Console
          </div>
          
          <ul className="sidebar-menu">
            <li 
              className={`menu-item ${qradarTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => setQradarTab('dashboard')}
            >
              📊 SIEM Dashboard
            </li>
            <li 
              className={`menu-item ${qradarTab === 'logs' ? 'active' : ''}`}
              onClick={() => setQradarTab('logs')}
            >
              📋 Log Activity
            </li>
            <li 
              className={`menu-item ${qradarTab === 'offenses' ? 'active' : ''}`}
              onClick={() => setQradarTab('offenses')}
            >
              🚨 Security Offenses
            </li>
            <li 
              className={`menu-item ${qradarTab === 'rules' ? 'active' : ''}`}
              onClick={() => setQradarTab('rules')}
            >
              ⚙️ Rule Policies
            </li>
            <li 
              className={`menu-item ${qradarTab === 'users' ? 'active' : ''}`}
              onClick={() => setQradarTab('users')}
            >
              👥 User Accounts
            </li>
          </ul>

          <div className="sidebar-footer">
            <button className="logout-btn" onClick={handleLogout}>
              Logout Console
            </button>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="main-content">
          
          {/* Top Navigation */}
          <div className="top-nav">
            <div className="nav-title">IBM Security QRadar SIEM</div>
            <div className="session-info">
              Admin Session Active | Database Connection: <span style={{ color: '#34d399', fontWeight: 'bold' }}>ONLINE</span>
            </div>
          </div>

          {/* Active Tab View */}
          <div className="content-body">
            
            {/* TAB 1: SIEM DASHBOARD OVERVIEW */}
            {qradarTab === 'dashboard' ? (
              <>
                <div className="content-header">
                  <h2>SIEM Overview Dashboard</h2>
                </div>

                {/* Dashboard Stats Cards Grid */}
                <div className="features-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px', marginBottom: '20px' }}>
                  <div className="feature-card" style={{ padding: '15px', backgroundColor: 'var(--panel-color)', border: '1px solid #333', textAlign: 'center' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>SIEM SYSTEM STATUS</span>
                    <h2 style={{ color: '#10b981', margin: '5px 0' }}>ONLINE</h2>
                    <span style={{ fontSize: '10px', color: '#10b981' }}>● Monitoring Active</span>
                  </div>

                  <div className="feature-card" style={{ padding: '15px', backgroundColor: 'var(--panel-color)', border: '1px solid #333', textAlign: 'center' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>TOTAL AUDITED LOGS</span>
                    <h2 style={{ color: 'var(--accent-blue)', margin: '5px 0' }}>{totalLogsCount}</h2>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{failedEventsCount} Failed Log Inserts</span>
                  </div>

                  <div className="feature-card" style={{ padding: '15px', backgroundColor: 'var(--panel-color)', border: '1px solid #333', textAlign: 'center' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>CONTAINED BLACKLISTS</span>
                    <h2 style={{ color: '#ef4444', margin: '5px 0' }}>{blockedIpsCount}</h2>
                    <span style={{ fontSize: '10px', color: '#ef4444' }}>IP Hosts Blocked</span>
                  </div>

                  <div className="feature-card" style={{ padding: '15px', backgroundColor: 'var(--panel-color)', border: '1px solid #333', textAlign: 'center' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>REGISTERED ACCOUNTS</span>
                    <h2 style={{ color: '#fbbf24', margin: '5px 0' }}>{registeredUsersCount}</h2>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Admins & Customers</span>
                  </div>
                </div>

                {/* Sub layout: Recent Alarms and Active Policies */}
                <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', marginTop: '20px' }}>
                  
                  {/* Left Panel: Recent Critical Security Events */}
                  <div className="table-container" style={{ flex: '2 1 450px', margin: 0 }}>
                    <h3 style={{ margin: '0 0 10px 0', color: '#ef4444' }}>🚨 Recent High-Risk Events (FAILED Logs)</h3>
                    <table>
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Username</th>
                          <th>IP Address</th>
                          <th>Incident Alert</th>
                        </tr>
                      </thead>
                      <tbody>
                        {logs.filter(l => l.status === 'FAILED').slice(0, 5).length === 0 ? (
                          <tr>
                            <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No failed incidents recorded. System secure.</td>
                          </tr>
                        ) : (
                          logs.filter(l => l.status === 'FAILED').slice(0, 5).map((log) => (
                            <tr key={log.id}>
                              <td style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{log.timestamp.slice(11, 19) || log.timestamp}</td>
                              <td><strong>{log.username}</strong></td>
                              <td>{log.ip_address}</td>
                              <td style={{ color: '#fca5a5', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {log.details}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Right Panel: Rules Quick Overview */}
                  <div className="bank-action-card" style={{ flex: '1 1 300px', backgroundColor: 'var(--panel-color)', margin: 0, height: 'fit-content' }}>
                    <h3 style={{ borderBottom: '1px solid #333', paddingBottom: '5px', margin: '0 0 10px 0' }}>🛡️ Active Security Policies</h3>
                    <ul style={{ listStyle: 'none', padding: 0, margin: 0, fontSize: '13px' }}>
                      <li style={{ padding: '8px 0', borderBottom: '1px solid #222', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Max Login Failure Policy:</span>
                        <strong>{rules.maxFailedLogins} attempts</strong>
                      </li>
                      <li style={{ padding: '8px 0', borderBottom: '1px solid #222', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Single Transfer Limit:</span>
                        <strong>₹{rules.maxTransferLimit.toLocaleString()}</strong>
                      </li>
                      <li style={{ padding: '8px 0', borderBottom: '1px solid #222', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Daily Transfer Limit:</span>
                        <strong>₹{rules.maxDailyTransferLimit.toLocaleString()}</strong>
                      </li>
                      <li style={{ padding: '8px 0', borderBottom: '1px solid #222', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Single Loan Limit:</span>
                        <strong>₹{rules.maxLoanLimit.toLocaleString()}</strong>
                      </li>
                      <li style={{ padding: '8px 0', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Daily Cumulative Loan Limit:</span>
                        <strong>₹{rules.maxDailyLoanLimit.toLocaleString()}</strong>
                      </li>
                    </ul>
                  </div>

                </div>
              </>
            ) : qradarTab === 'logs' ? (
              <>
                <div className="content-header">
                  <h2>Log Activity Logs</h2>
                  <button className="btn-action btn-success" onClick={handleExport}>
                    📥 Export logs to CSV (Excel)
                  </button>
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Username</th>
                        <th>Source IP</th>
                        <th>Device Name</th>
                        <th>Location</th>
                        <th>Status</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.length === 0 ? (
                        <tr>
                          <td colSpan="7" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No audit events found.</td>
                        </tr>
                      ) : (
                        logs.map((log) => (
                          <tr key={log.id}>
                            <td style={{ color: 'var(--text-muted)' }}>{log.timestamp}</td>
                            <td><strong>{log.username}</strong></td>
                            <td>{log.ip_address}</td>
                            <td>{log.device_name}</td>
                            <td>{log.location}</td>
                            <td>
                              <span className={`badge ${log.status === 'SUCCESS' ? 'badge-success' : 'badge-failed'}`}>
                                {log.status}
                              </span>
                            </td>
                            <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={log.details}>
                              {log.details}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            ) : qradarTab === 'offenses' ? (
              <>
                <div className="content-header">
                  <h2>Security Offenses (Intrusion Alerts)</h2>
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Offense ID</th>
                        <th>Source IP</th>
                        <th>Rule Violated</th>
                        <th>Severity</th>
                        <th>Failed Attempts</th>
                        <th>Status</th>
                        <th>Last Detected</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {offenses.length === 0 ? (
                        <tr>
                          <td colSpan="8" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No active offenses recorded.</td>
                        </tr>
                      ) : (
                        offenses.map((offense) => (
                          <tr key={offense.id}>
                            <td>#{offense.id}</td>
                            <td><strong>{offense.source_ip}</strong></td>
                            <td style={{ color: '#fbbf24' }}>{offense.offense_type}</td>
                            <td>
                              <span className="badge badge-severity-high">
                                {offense.severity}
                              </span>
                            </td>
                            <td style={{ textAlign: 'center' }}>{offense.failed_attempts}</td>
                            <td>
                              <span className={`badge ${offense.status === 'BLOCKED' ? 'badge-failed' : 'badge-success'}`}>
                                {offense.status}
                              </span>
                            </td>
                            <td style={{ color: 'var(--text-muted)' }}>{offense.last_detected}</td>
                            <td>
                              {offense.status === 'BLOCKED' ? (
                                <span 
                                  className="action-link"
                                  onClick={() => handleUnblock(offense.source_ip)}
                                >
                                  🔓 Unblock & Clear IP
                                </span>
                              ) : (
                                <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Cleared</span>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            ) : qradarTab === 'rules' ? (
              <>
                <div className="content-header">
                  <h2>SIEM Correlation Rules & Safety Thresholds</h2>
                </div>
                
                <div className="bank-action-card" style={{ maxWidth: '600px', backgroundColor: 'var(--panel-color)' }}>
                  <form onSubmit={handleSaveRules}>
                    <h4 style={{ margin: '0 0 10px 0', borderBottom: '1px solid #333', paddingBottom: '5px' }}>Authentication Policy</h4>
                    <div className="form-group">
                      <label>Max Login Failure Attempts (Before Blocking IP)</label>
                      <input 
                        type="number" 
                        value={rules.maxFailedLogins} 
                        onChange={(e) => setRules({ ...rules, maxFailedLogins: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <h4 style={{ margin: '15px 0 10px 0', borderBottom: '1px solid #333', paddingBottom: '5px' }}>Single Transaction Limits</h4>
                    <div className="form-group">
                      <label>Max Single Deposit Limit (₹)</label>
                      <input 
                        type="number" 
                        value={rules.maxDepositLimit} 
                        onChange={(e) => setRules({ ...rules, maxDepositLimit: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <div className="form-group">
                      <label>Max Single Transfer Limit (₹)</label>
                      <input 
                        type="number" 
                        value={rules.maxTransferLimit} 
                        onChange={(e) => setRules({ ...rules, maxTransferLimit: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <div className="form-group">
                      <label>Max Single Loan Request Limit (₹)</label>
                      <input 
                        type="number" 
                        value={rules.maxLoanLimit} 
                        onChange={(e) => setRules({ ...rules, maxLoanLimit: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <h4 style={{ margin: '15px 0 10px 0', borderBottom: '1px solid #333', paddingBottom: '5px' }}>Daily Cumulative Limits (Structuring Fraud Prevention)</h4>
                    <div className="form-group">
                      <label>Max Daily Cumulative Deposit Limit (₹)</label>
                      <input 
                        type="number" 
                        value={rules.maxDailyDepositLimit} 
                        onChange={(e) => setRules({ ...rules, maxDailyDepositLimit: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <div className="form-group">
                      <label>Max Daily Cumulative Transfer Limit (₹)</label>
                      <input 
                        type="number" 
                        value={rules.maxDailyTransferLimit} 
                        onChange={(e) => setRules({ ...rules, maxDailyTransferLimit: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <div className="form-group">
                      <label>Max Daily Cumulative Loan Limit (₹)</label>
                      <input 
                        type="number" 
                        value={rules.maxDailyLoanLimit} 
                        onChange={(e) => setRules({ ...rules, maxDailyLoanLimit: parseInt(e.target.value) || 0 })}
                        required 
                      />
                    </div>

                    <button type="submit" className="login-btn" style={{ backgroundColor: 'var(--accent-blue)', marginTop: '15px' }}>
                      💾 Save & Apply Security Policies
                    </button>
                  </form>
                </div>
              </>
            ) : (
              // USER ACCOUNTS TAB VIEW
              <>
                <div className="content-header">
                  <h2>User Accounts Manager</h2>
                </div>

                <div className="dashboard-layout" style={{ display: 'flex', gap: '20px', flexDirection: 'row', flexWrap: 'wrap' }}>
                  {/* Left Column: Actions Forms */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', flex: '1 1 350px' }}>
                    {/* Create user form */}
                    <div className="bank-action-card" style={{ backgroundColor: 'var(--panel-color)', margin: 0 }}>
                      <h3>Create New Profile</h3>
                      <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Register Bank Customers (USER) or Security Administrators (ADMIN).
                      </p>

                      <form onSubmit={handleCreateUser}>
                        <div className="form-group">
                          <label>Account Username</label>
                          <input 
                            type="text"
                            placeholder="e.g. rajesh_kumar"
                            value={newUserUsername}
                            onChange={(e) => setNewUserUsername(e.target.value)}
                            required
                          />
                        </div>

                        <div className="form-group">
                          <label>Secure Password</label>
                          <input 
                            type="password"
                            placeholder="e.g. rajeshPass321"
                            value={newUserPassword}
                            onChange={(e) => setNewUserPassword(e.target.value)}
                            required
                          />
                        </div>

                        <div className="form-group">
                          <label>Portal Role / Authorization</label>
                          <select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value)}>
                            <option value="USER">Bank Customer (USER)</option>
                            <option value="ADMIN">Security Admin (ADMIN)</option>
                          </select>
                        </div>

                        <button type="submit" className="login-btn" style={{ backgroundColor: 'var(--accent-blue)' }}>
                          👤 Register Account
                        </button>
                      </form>
                    </div>

                    {/* Change Password Form */}
                    <div className="bank-action-card" style={{ backgroundColor: 'var(--panel-color)', margin: 0 }}>
                      <h3>Modify Account Password</h3>
                      <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Update the security password for any user or admin account.
                      </p>

                      <form onSubmit={handleAdminChangePassword}>
                        <div className="form-group">
                          <label>Select Account</label>
                          <select 
                            value={changePwdUsername} 
                            onChange={(e) => setChangePwdUsername(e.target.value)}
                            required
                          >
                            {usersList.map((usr) => (
                              <option key={usr.id} value={usr.username}>
                                {usr.username} ({usr.role})
                              </option>
                            ))}
                          </select>
                        </div>

                        <div className="form-group">
                          <label>New Password</label>
                          <input 
                            type="password"
                            placeholder="Enter new password"
                            value={changePwdNewPassword}
                            onChange={(e) => setChangePwdNewPassword(e.target.value)}
                            required
                          />
                        </div>

                        <button type="submit" className="login-btn" style={{ backgroundColor: '#fbbf24', color: '#111' }}>
                          🔑 Update Password
                        </button>
                      </form>
                    </div>
                  </div>

                  {/* Right Column: User list */}
                  <div className="table-container" style={{ flex: '2 1 450px', margin: 0 }}>
                    <h3 style={{ margin: '0 0 10px 0' }}>Registered Accounts List</h3>
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Username</th>
                          <th>Role</th>
                        </tr>
                      </thead>
                      <tbody>
                        {usersList.length === 0 ? (
                          <tr>
                            <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No accounts registered.</td>
                          </tr>
                        ) : (
                          usersList.map((usr) => (
                            <tr key={usr.id}>
                              <td>#{usr.id}</td>
                              <td><strong>{usr.username}</strong></td>
                              <td>
                                <span className={`badge ${usr.role === 'ADMIN' ? 'badge-failed' : 'badge-success'}`} style={{ textTransform: 'uppercase' }}>
                                  {usr.role}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
