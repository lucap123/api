// src/index.js

const { Pool } = require('pg');

// This function will be executed by Appwrite
export default async ({ req, res, log, error }) => {
  // Appwrite provides the body as a string, so we need to parse it.
  // We also check if the body is empty or malformed.
  let machineId, key;
  try {
    const body = JSON.parse(req.body);
    machineId = body.machineId;
    key = body.key;
  } catch (e) {
    error('Invalid JSON body provided.');
    return res.json({ success: false, message: 'Invalid request body.' }, 400);
  }

  // 1. Basic input validation
  if (!machineId || !key) {
    log('Missing machineId or key in request.');
    return res.json({ success: false, message: 'Machine ID and key are required.' }, 400);
  }

  // --- Database Connection ---
  // We will get the DATABASE_URL from the function's environment variables.
  if (!process.env.DATABASE_URL) {
    error('DATABASE_URL environment variable is not set.');
    return res.json({ success: false, message: 'Server configuration error.' }, 500);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  });

  try {
    // 2. Look for the key in the database
    const query = 'SELECT id, expires_at, machine_id FROM user_keys WHERE key_value = $1';
    const { rows } = await pool.query(query, [key]);

    if (rows.length === 0) {
      log(`Invalid key used: ${key}`);
      // NOTE: Appwrite's res.json() takes the body first, then the status code.
      return res.json({ success: false, message: 'Invalid key.' }, 404);
    }

    const license = rows[0];

    // 3. Check if the key is expired
    const expirationDate = new Date(license.expires_at);
    if (expirationDate < new Date()) {
      log(`Expired key used: ${key}`);
      return res.json({ success: false, message: 'This key has expired.' }, 403);
    }

    // 4. Check the machine ID associated with the key

    // SCENARIO A: Key is valid and belongs to this machine.
    if (license.machine_id && license.machine_id === machineId) {
      log(`Successful login for Machine ID: ${machineId}`);
      return res.json({ success: true, message: 'Login successful.' }, 200);
    }

    // SCENARIO B: Key is valid but is already used by another machine.
    if (license.machine_id && license.machine_id !== machineId) {
      log(`Key ${key} is assigned to another machine. Attempted by ${machineId}.`);
      return res.json({ success: false, message: 'Key is already in use by another machine.' }, 403);
    }

    // SCENARIO C: Key is new/unclaimed. Assign it to this machine.
    if (!license.machine_id) {
      const updateQuery = 'UPDATE user_keys SET machine_id = $1 WHERE key_value = $2';
      await pool.query(updateQuery, [machineId, key]);
      
      log(`Key ${key} has been activated for Machine ID: ${machineId}`);
      return res.json({ success: true, message: 'Key successfully activated. Login successful.' }, 200);
    }

    // Fallback case
    error('Reached an unhandled case in the logic.');
    return res.json({ success: false, message: 'An unexpected error occurred.' }, 500);

  } catch (dbError) {
    error('Database Error:', dbError.message);
    return res.json({ success: false, message: 'Internal Server Error.' }, 500);
  } finally {
    // Close the database connection pool
    await pool.end();
  }
};
