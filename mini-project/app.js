// app.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'crazyBids2025SecretKey';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database setup
const db = new sqlite3.Database('./crazyBids.db', (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table with role field
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      credits REAL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Products table
    db.run(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      image_url TEXT
    )`);

    // Auction listings table
    db.run(`CREATE TABLE IF NOT EXISTS auction_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      starting_bid REAL NOT NULL,
      reserve_price REAL,
      current_price REAL,
      start_date DATETIME NOT NULL,
      end_date DATETIME NOT NULL,
      status TEXT DEFAULT 'pending',
      winner_id INTEGER,
      FOREIGN KEY (product_id) REFERENCES products (id),
      FOREIGN KEY (winner_id) REFERENCES users (id)
    )`);

    // Bids table
    db.run(`CREATE TABLE IF NOT EXISTS bids (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      auction_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      bid_amount REAL NOT NULL,
      bid_time DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (auction_id) REFERENCES auction_listings (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Insert some sample data
    db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
      if (err) {
        console.error(err.message);
      } else if (row.count === 0) {
        // Insert sample products
        db.run(`INSERT INTO products (name, description, image_url) VALUES 
          ('MacBook Pro', 'Latest model with M3 chip', 'macbook.jpg'),
          ('iPhone 15 Pro', '256GB Titanium Gray', 'iphone.jpg'),
          ('Sony PlayStation 5', 'Digital Edition with extra controller', 'ps5.jpg')`);
          
        // Insert sample auction listings
        const now = new Date();
        const oneWeekLater = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        
        db.run(`INSERT INTO auction_listings 
          (product_id, starting_bid, reserve_price, current_price, start_date, end_date, status) VALUES 
          (1, 500, 1200, 500, ?, ?, 'active'),
          (2, 300, 800, 300, ?, ?, 'active'),
          (3, 200, 450, 200, ?, ?, 'active')`, 
          [now.toISOString(), oneWeekLater.toISOString(), 
           now.toISOString(), oneWeekLater.toISOString(),
           now.toISOString(), oneWeekLater.toISOString()]);
      }
    });

    // Check if employee exists, if not create one
    db.get("SELECT COUNT(*) as count FROM users WHERE role = 'employee'", async (err, row) => {
      if (err) {
        console.error(err.message);
      } else if (row.count === 0) {
        // Create default employee account
        const hashedPassword = await bcrypt.hash('admin123', 10);
        db.run(`INSERT INTO users (username, email, password, role) VALUES 
          ('admin', 'admin@crazybids.com', ?, 'employee')`, [hashedPassword]);
        console.log('Default employee account created');
      }
    });
  });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Middleware to check if user is an employee
function isEmployee(req, res, next) {
  if (req.user.role !== 'employee') {
    return res.status(403).json({ error: 'Access denied. Employee privileges required.' });
  }
  next();
}

// Calculate bid increment based on current price
function calculateBidIncrement(currentPrice) {
  if (currentPrice < 1) return 0.05;
  if (currentPrice < 5) return 0.25;
  if (currentPrice < 25) return 0.50;
  if (currentPrice < 100) return 1.00;
  if (currentPrice < 250) return 2.50;
  if (currentPrice < 500) return 5.00;
  if (currentPrice < 1000) return 10.00;
  if (currentPrice < 2500) return 25.00;
  if (currentPrice < 5000) return 50.00;
  return 100.00;
}

// Routes
// 1. User Registration
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert new user (always as regular user)
    db.run('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', 
      [username, email, hashedPassword, 'user'], 
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: err.message });
        }
        
        // Generate JWT token
        const token = jwt.sign({ 
          id: this.lastID, 
          username, 
          role: 'user' 
        }, JWT_SECRET, { expiresIn: '24h' });
        
        res.status(201).json({ 
          message: 'User registered successfully', 
          token,
          userId: this.lastID,
          username,
          role: 'user'
        });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    
    try {
      // Compare password
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ error: 'Invalid email or password' });
      
      // Generate JWT token with role
      const token = jwt.sign({ 
        id: user.id, 
        username: user.username,
        role: user.role 
      }, JWT_SECRET, { expiresIn: '24h' });
      
      res.json({ 
        message: 'Login successful', 
        token,
        userId: user.id,
        username: user.username,
        role: user.role,
        credits: user.credits
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
});


// User add credits into their account
app.post('/add_credits', authenticateToken, (req, res) => {
  const { amount } = req.body;
  const userId = req.user.id;
  
  // Check if amount is a positive numb
  db.run('UPDATE users SET credits = credits + ? WHERE id = ?', [amount, userId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Credits added successfully', credits: amount });
  });
});


// 3. Get Active Auction Listings
app.get('/auctions/active', (req, res) => {
  const now = new Date().toISOString();
  
  db.all(`
    SELECT a.*, p.name as product_name, p.description, p.image_url, 
           (SELECT COUNT(*) FROM bids WHERE auction_id = a.id) as bid_count,
           (SELECT username FROM users WHERE id = 
              (SELECT user_id FROM bids WHERE auction_id = a.id ORDER BY bid_amount DESC LIMIT 1)
           ) as highest_bidder
    FROM auction_listings a
    JOIN products p ON a.product_id = p.id
    WHERE a.start_date <= ? AND a.end_date >= ? AND a.status = 'active'
    ORDER BY a.end_date ASC
  `, [now, now], (err, auctions) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Add bid increment to each auction
    auctions.forEach(auction => {
      auction.bid_increment = calculateBidIncrement(auction.current_price);
      auction.minimum_bid = auction.current_price + auction.bid_increment;
    });
    
    res.json(auctions);
  });
});

// 4. Place a Bid
app.post('/auctions/:id/bid', authenticateToken, (req, res) => {
  const auctionId = req.params.id;
  const { bid_amount } = req.body;
  const userId = req.user.id;
  
  if (!bid_amount || isNaN(bid_amount)) {
    return res.status(400).json({ error: 'Valid bid amount is required' });
  }
  
  // Start a transaction
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    
    // Get the auction details
    db.get(`
      SELECT a.*, u.credits 
      FROM auction_listings a
      JOIN users u ON u.id = ?
      WHERE a.id = ? AND a.status = 'active' AND a.end_date >= datetime('now')
    `, [userId, auctionId], (err, auction) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: err.message });
      }
      
      if (!auction) {
        db.run('ROLLBACK');
        return res.status(404).json({ error: 'Auction not found or not active' });
      }
      
      // Check if user has enough credits
      if (auction.credits < bid_amount) {
        db.run('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient credits' });
      }
      
      // Calculate minimum valid bid
      const minBid = auction.current_price + calculateBidIncrement(auction.current_price);
      
      if (bid_amount < minBid) {
        db.run('ROLLBACK');
        return res.status(400).json({ 
          error: 'Bid amount too low', 
          minimum_bid: minBid,
          current_price: auction.current_price,
          bid_increment: calculateBidIncrement(auction.current_price)
        });
      }
      
      // Record the bid
      db.run('INSERT INTO bids (auction_id, user_id, bid_amount) VALUES (?, ?, ?)',
        [auctionId, userId, bid_amount], function(err) {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: err.message });
          }
          
          // Update the auction current price
          db.run('UPDATE auction_listings SET current_price = ? WHERE id = ?',
            [bid_amount, auctionId], function(err) {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: err.message });
              }
              
              db.run('COMMIT');
              res.json({ 
                message: 'Bid placed successfully',
                bid_id: this.lastID,
                auction_id: auctionId,
                amount: bid_amount
              });
            }
          );
        }
      );
    });
  });
});

// 5. Get Auction Details with Bids History
app.get('/auctions/:id', (req, res) => {
  const auctionId = req.params.id;
  
  db.get(`
    SELECT a.*, p.name as product_name, p.description, p.image_url
    FROM auction_listings a
    JOIN products p ON a.product_id = p.id
    WHERE a.id = ?
  `, [auctionId], (err, auction) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!auction) return res.status(404).json({ error: 'Auction not found' });
    
    // Get bid history
    db.all(`
      SELECT b.id, b.bid_amount, b.bid_time, u.username
      FROM bids b
      JOIN users u ON b.user_id = u.id
      WHERE b.auction_id = ?
      ORDER BY b.bid_amount DESC
    `, [auctionId], (err, bids) => {
      if (err) return res.status(500).json({ error: err.message });
      
      auction.bids = bids;
      auction.bid_count = bids.length;
      auction.bid_increment = calculateBidIncrement(auction.current_price);
      auction.minimum_bid = auction.current_price + auction.bid_increment;
      
      res.json(auction);
    });
  });
});

// 6. Create Auction Listing (Employee only)
app.post('/auctions', authenticateToken, isEmployee, (req, res) => {
  const { product_id, starting_bid, reserve_price, start_date, end_date } = req.body;
  
  if (!product_id || !starting_bid || !start_date || !end_date) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const startDate = new Date(start_date);
  const endDate = new Date(end_date);
  
  if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
    return res.status(400).json({ error: 'Invalid date format' });
  }
  
  if (endDate <= startDate) {
    return res.status(400).json({ error: 'End date must be after start date' });
  }
  
  db.run(`
    INSERT INTO auction_listings 
    (product_id, starting_bid, reserve_price, current_price, start_date, end_date, status) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    product_id, 
    starting_bid, 
    reserve_price || null, 
    starting_bid, 
    startDate.toISOString(), 
    endDate.toISOString(),
    'active'
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    
    res.status(201).json({
      message: 'Auction created successfully',
      auction_id: this.lastID
    });
  });
});

// 7. Create Product (Employee only)
app.post('/products', authenticateToken, isEmployee, (req, res) => {
  const { name, description, image_url } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: 'Product name is required' });
  }
  
  db.run(`
    INSERT INTO products (name, description, image_url)
    VALUES (?, ?, ?)
  `, [name, description || null, image_url || null], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    
    res.status(201).json({
      message: 'Product created successfully',
      product_id: this.lastID,
      name: name
    });
  });
});

// 8. Get all products (for employees to select when creating auctions)
app.get('/products', authenticateToken, isEmployee, (req, res) => {
  db.all('SELECT * FROM products ORDER BY id DESC', (err, products) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(products);
  });
});

// 9. Get User's Bid History
app.get('/users/bids', authenticateToken, (req, res) => {
  const userId = req.user.id;
  
  db.all(`
    SELECT b.id as bid_id, b.bid_amount, b.bid_time, 
           a.id as auction_id, a.current_price, a.end_date, a.status,
           p.id as product_id, p.name as product_name, p.image_url,
           (b.bid_amount = a.current_price) as is_highest_bid
    FROM bids b
    JOIN auction_listings a ON b.auction_id = a.id
    JOIN products p ON a.product_id = p.id
    WHERE b.user_id = ?
    ORDER BY b.bid_time DESC
  `, [userId], (err, bids) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Format the response
    const formattedBids = bids.map(bid => {
      return {
        bid_id: bid.bid_id,
        auction_id: bid.auction_id,
        product: {
          id: bid.product_id,
          name: bid.product_name,
          image_url: bid.image_url
        },
        bid_amount: bid.bid_amount,
        bid_time: bid.bid_time,
        auction_status: bid.status,
        auction_end_date: bid.end_date,
        is_highest_bid: bid.is_highest_bid === 1,
        current_auction_price: bid.current_price
      };
    });
    
    res.json({
      user_id: userId,
      username: req.user.username,
      total_bids: formattedBids.length,
      bids: formattedBids
    });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Database connection closed');
    process.exit(0);
  });
});