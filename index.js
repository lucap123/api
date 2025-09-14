// index.js (Updated for Auto-Login)

const { Pool } = require('pg');

module.exports = async ({ req, res, log, error }) => {
  const { machineId, key } = req.body;

  // 1. A Machine ID is always required.
  if (!machineId) {
    log('Missing machineId in request.');
    return res.json({ success: false, message: 'Machine ID is required.' }, 400);
  }

  // --- Database Connection ---
  if (!process.env.DATABASE_URL) {
    error('DATABASE_URL environment variable is not set.');
    return res.json({ success: false, message: 'Server configuration error.' }, 500);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  try {
    // --- FLOW 1: AUTO-LOGIN (No key provided) ---
    // Checks if the machineId is already registered and valid.
    if (!key) {
      log(`Auto-login attempt for Machine ID: ${machineId}`);
      const query = 'SELECT expires_at FROM user_keys WHERE machine_id = $1';
      const { rows } = await pool.query(query, [machineId]);

      if (rows.length === 0) {
        log(`Machine ID ${machineId} not found for auto-login.`);
        // Use a 404 status code to signal the client it needs to activate.
        return res.json({ success: false, message: 'Machine not registered. Please activate.' }, 404);
      }

      const license = rows[0];
      const expirationDate = new Date(license.expires_at);
      if (expirationDate < new Date()) {
        log(`License for Machine ID ${machineId} has expired.`);
        return res.json({ success: false, message: 'Your license has expired.' }, 403);
      }

      log(`Successful auto-login for Machine ID: ${machineId}`);
      return res.json({ success: true, message: 'Welcome back! Login successful.' }, 200);
    }

    // --- FLOW 2: ACTIVATION / VALIDATION (Key is provided) ---
    // Runs the original activation logic.
    if (key) {
      log(`Activation attempt with key on Machine ID: ${machineId}`);
      const query = 'SELECT id, expires_at, machine_id FROM user_keys WHERE key_value = $1';
      const { rows } = await pool.query(query, [key]);

      if (rows.length === 0) {
        return res.json({ success: false, message: 'Invalid key.' }, 404);
      }

      const license = rows[0];

      // Check expiration
      const expirationDate = new Date(license.expires_at);
      if (expirationDate < new Date()) {
        return res.json({ success: false, message: 'This key has expired.' }, 403);
      }

      // Check if machine ID is already associated
      if (license.machine_id && license.machine_id === machineId) {
        return res.json({ success: true, message: 'Login successful.' }, 200);
      }
      if (license.machine_id && license.machine_id !== machineId) {
        return res.json({ success: false, message: 'Key is already in use by another machine.' }, 403);
      }
      
      // THIS IS THE CRITICAL STEP: Associate the key with the machineId
      if (!license.machine_id) {
        const updateQuery = 'UPDATE user_keys SET machine_id = $1 WHERE key_value = $2';
        await pool.query(updateQuery, [machineId, key]);
        log(`Key ${key} has been activated for Machine ID: ${machineId}`);
        return res.json({ success: true, message: 'Key successfully activated. Login successful.' }, 200);
      }
    }

  } catch (dbError) {
    error('Database Error:', dbError.message);
    return res.json({ success: false, message: 'Internal Server Error.' }, 500);
  } finally {
    await pool.end();
  }
};
