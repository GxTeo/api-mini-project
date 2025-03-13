// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3001;
const JWT_SECRET = 'your_jwt_secret_key';

app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database('./flight_reservation.db', (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database');
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    // Create tables
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'customer'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS flights (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      flight_number TEXT NOT NULL,
      origin TEXT NOT NULL,
      destination TEXT NOT NULL,
      departure_time TEXT NOT NULL,
      arrival_time TEXT NOT NULL,
      aircraft_type TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS seats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      flight_id INTEGER,
      seat_number TEXT NOT NULL,
      cabin_class TEXT NOT NULL,
      price REAL NOT NULL,
      is_available BOOLEAN DEFAULT 1,
      FOREIGN KEY (flight_id) REFERENCES flights (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reservations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      flight_id INTEGER,
      seat_id INTEGER,
      booking_reference TEXT UNIQUE NOT NULL,
      booking_date TEXT NOT NULL,
      status TEXT DEFAULT 'confirmed',
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (flight_id) REFERENCES flights (id),
      FOREIGN KEY (seat_id) REFERENCES seats (id)
    )`);

    // Insert seed data for employees
    db.get("SELECT COUNT(*) as count FROM users WHERE role = 'employee'", (err, row) => {
      if (err) {
        console.error(err.message);
      } else if (row.count === 0) {
        // Insert a default employee if none exists
        bcrypt.hash('employee123', 10, (err, hash) => {
          if (err) console.error(err);
          else {
            db.run("INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)",
              ['employee@merlionair.com', hash, 'Admin Employee', 'employee']);
          }
        });
      }
    });

    // Insert sample flights
    db.get("SELECT COUNT(*) as count FROM flights", (err, row) => {
      if (err) {
        console.error(err.message);
      } else if (row.count === 0) {
        // Insert sample flights
        const flights = [
          ['ML123', 'SIN', 'NRT', '2025-01-15 08:00:00', '2025-01-15 16:00:00', 'Boeing 747'],
          ['ML456', 'SYD', 'SIN', '2025-01-15 09:30:00', '2025-01-15 14:30:00', 'Boeing 737'],
          ['ML789', 'SYD', 'NRT', '2025-01-16 07:00:00', '2025-01-16 17:00:00', 'Boeing 747']
        ];
        
        flights.forEach(flight => {
          db.run(`INSERT INTO flights (flight_number, origin, destination, departure_time, arrival_time, aircraft_type) 
                  VALUES (?, ?, ?, ?, ?, ?)`, flight);
        });
        
        // Add some seats for each flight
        setTimeout(() => {
          db.all("SELECT id FROM flights", [], (err, flights) => {
            if (err) {
              console.error(err.message);
            } else {
              flights.forEach(flight => {
                // Add economy seats
                for (let i = 1; i <= 30; i++) {
                  for (let seat of ['A', 'B', 'C', 'D', 'E', 'F']) {
                    db.run(`INSERT INTO seats (flight_id, seat_number, cabin_class, price) 
                           VALUES (?, ?, ?, ?)`, [flight.id, `${i}${seat}`, 'economy', 299.99]);
                  }
                }
                
                // Add business seats
                for (let i = 1; i <= 10; i++) {
                  for (let seat of ['A', 'B', 'C', 'D']) {
                    db.run(`INSERT INTO seats (flight_id, seat_number, cabin_class, price) 
                           VALUES (?, ?, ?, ?)`, [flight.id, `${i}${seat}`, 'business', 899.99]);
                  }
                }
              });
            }
          });
        }, 1000);
      }
    });
  });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Employee role middleware
function employeeOnly(req, res, next) {
  if (req.user.role !== 'employee') {
    return res.status(403).json({ error: 'Employees only' });
  }
  next();
}

// Authentication routes
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  try {
    // Check if user already exists
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (user) {
        return res.status(409).json({ error: 'User already exists' });
      }
      
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Create new user
      db.run('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', 
        [email, hashedPassword, name], function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          const token = jwt.sign(
            { id: this.lastID, email, name, role: 'customer' }, 
            JWT_SECRET, 
            { expiresIn: '1h' }
          );
          
          res.status(201).json({ 
            message: 'User registered successfully',
            token,
            user: { id: this.lastID, email, name, role: 'customer' }
          });
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );
    
    res.json({ 
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  });
});

// Flight search endpoint
app.get('/api/flights/search', (req, res) => {
  const { origin, destination, departure_date } = req.body;
  
  console.log(origin, destination, departure_date);
  if (!origin || !destination || !departure_date) {
    return res.status(400).json({ error: 'Origin, destination, and departure date are required' });
  }
  
  // Format the date to match SQLite storage (assuming YYYY-MM-DD format)
  const date = departure_date.split('T')[0];
  const datePattern = `${date}%`;
  
  db.all(`SELECT f.*, 
         (SELECT MIN(price) FROM seats WHERE flight_id = f.id AND cabin_class = 'economy') as economy_price,
         (SELECT MIN(price) FROM seats WHERE flight_id = f.id AND cabin_class = 'business') as business_price
         FROM flights f 
         WHERE f.origin = ? AND f.destination = ? AND f.departure_time LIKE ?`,
    [origin, destination, datePattern],
    (err, flights) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ flights });
    });
});

// Get available seats for a flight and cabin class
app.get('/api/flights/:flightId/seats', (req, res) => {
    const { flightId, cabin_class } = req.body;
  
  let query = 'SELECT * FROM seats WHERE flight_id = ? AND is_available = 1';
  let params = [flightId];
  
  if (cabin_class) {
    query += ' AND cabin_class = ?';
    params.push(cabin_class);
  }
  
  db.all(query, params, (err, seats) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    res.json({ seats });
  });
});

// Create reservation endpoint
app.post('/api/reservations', authenticateToken, (req, res) => {
  const { flight_id, seat_id } = req.body;
  const user_id = req.user.id;
  
  if (!flight_id || !seat_id) {
    return res.status(400).json({ error: 'Flight ID and seat ID are required' });
  }
  
  // Check if the seat is available
  db.get('SELECT * FROM seats WHERE id = ? AND is_available = 1', [seat_id], (err, seat) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!seat) {
      return res.status(400).json({ error: 'Selected seat is not available' });
    }
    
    // Generate a booking reference (simple implementation)
    const bookingReference = 'ML' + Math.floor(100000 + Math.random() * 900000);
    const bookingDate = new Date().toISOString();
    
    // Start a transaction
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      // Mark the seat as unavailable
      db.run('UPDATE seats SET is_available = 0 WHERE id = ?', [seat_id], function(err) {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }
        
        // Create the reservation
        db.run(`INSERT INTO reservations 
                (user_id, flight_id, seat_id, booking_reference, booking_date) 
                VALUES (?, ?, ?, ?, ?)`,
          [user_id, flight_id, seat_id, bookingReference, bookingDate],
          function(err) {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: err.message });
            }
            
            db.run('COMMIT');
            
            // Get the complete reservation details
            db.get(`SELECT r.*, f.flight_number, f.origin, f.destination, 
                    f.departure_time, f.arrival_time, s.seat_number, s.cabin_class, s.price 
                    FROM reservations r
                    JOIN flights f ON r.flight_id = f.id
                    JOIN seats s ON r.seat_id = s.id
                    WHERE r.id = ?`,
              [this.lastID],
              (err, reservation) => {
                if (err) {
                  return res.status(500).json({ error: err.message });
                }
                
                res.status(201).json({
                  message: 'Reservation created successfully',
                  reservation
                });
              });
          });
      });
    });
  });
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});