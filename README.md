# edu-web-security-passport

## Structure

```
/src
    /auth
        passport_config.js
    /routes
        auth_routes.js
    service.js
    server.js
```


## Instructions

```bash
mkdir auth-server && cd auth-server
npm install passport passport-local

npm init -y
npm install express express-validator cors bcrypt jsonwebtoken dotenv
npm install -D nodemon jest

npm pkg set main="./src/service.js"
npm pkg set scripts.start="node ./src/service.js"
npm pkg set scripts.dev="nodemon ./src/service.js"
npm pkg set scripts.test="jest"

# Create files
mkdir -p ./src/{routes,auth}
touch ./src/service.js ./src/server.js ./src/routes/auth_routes.js ./src/auth/passport_settings.js

```

## Auth Servder

### ./src/service.js

```js
cat > ./src/service.js << 'EOF'
require('dotenv').config();
const app = require('./server.js');
const PORT = process.env.PORT || 3001

app.listen(PORT, () => {
    console.log(`http server listening on port ${PORT}`)
});
EOF
```

### ./src/server.js

```js
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const authRoutes = require('./routes/auth_routes');
require('./auth/passport_config.js');  // Importing the Passport setup

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(passport.initialize());

// Routes
app.use('/auth', authRoutes);

module.exports = app;
EOF
```

### ./src/auth/users.js

```js
cat > ./src/auth/users.js << 'EOF'
const bcrypt = require("bcrypt");
const users = [
    { id: 1, email: 'user@example.com', password: bcrypt.hashSync('password', 10), role: 'user' }
];  // Example user store

module.exports = users;
EOF
```

### ./src/auth/passport_config.js

```js
cat > ./src/auth/passport_config.js << 'EOF'
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const users = require('./users');



passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    },
    async (email, password, done) => {
        const user = users.find(u => u.email === email);
        if (user == null) {
            return done(null, false, { message: 'No user with that email' });
        }

        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    }
));

module.exports = passport;
EOF
```

### ./src/routes/auth_routes.js

```js
cat > ./src/routes/auth_routes.js << 'EOF'
const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { check, validationResult } = require('express-validator');

const router = express.Router();
const users = require('../auth/users');

router.post('/login',
  [
    check('email').isEmail().withMessage('Enter a valid email address'),
    check('password').notEmpty().withMessage('Password cannot be empty')
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    next();
  },
  passport.authenticate('local', { session: false }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user.id, role: req.user.role }, 'YourJWTSecretKey', { expiresIn: '1h' });
    res.json({ token });
  }
);

router.post('/register',
  [
    check('email').isEmail().withMessage('Enter a valid email address'),
    check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters')
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    if (users.find(u => u.email === email)) return res.status(400).json({ message: 'User already exists' });

    // Hashing the password
    const hashedPassword = bcrypt.hashSync(password, 10);
    // Adding user to the "database"
    const newUser = { id: users.length + 1, email, password: hashedPassword, role: 'user' };
    users.push(newUser);
    
    res.status(201).json({ message: 'User registered successfully' });
  }
);

router.get('/users', (req, res) => {
  // Creating a user list without exposing passwords
  const userList = users.map(user => {
    return { id: user.id, email: user.email, password: user.password };
  });
  res.json(userList);
});

module.exports = router;
EOF
```

### Test it 

```bash

curl -X POST \
  http://localhost:3001/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "newuser@example.com",
    "password": "securepassword"
  }'

curl -X POST \
  http://localhost:3001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "newuser@example.com",
    "password": "securepassword"
  }'

```

## Backend server

## Instructions

```bash
mkdir backend-server && cd backend-server

npm init -y
npm install express cors bcrypt jsonwebtoken dotenv
npm install -D nodemon jest

npm pkg set main="./src/service.js"
npm pkg set scripts.start="node ./src/service.js"
npm pkg set scripts.dev="nodemon ./src/service.js"
npm pkg set scripts.test="jest"

# Create files
mkdir -p ./src/routes
touch ./src/service.js ./src/server.js ./src/routes/data_routes.js

```

### ./src/service.js

```js
cat > ./src/service.js << 'EOF'
require('dotenv').config();
const app = require('./server.js');
const PORT = process.env.PORT || 3002

app.listen(PORT, () => {
    console.log(`http server listening on port ${PORT}`)
});
EOF
```

### ./src/server.js

```js
cat > ./src/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dataRoutes = require('./routes/data_routes');

const app = express();
app.use(cors());
app.use(express.json());

// JWT Authentication Middleware
app.use((req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return next();  // No token, proceed without user object in req

    try {
        const verified = jwt.verify(token, 'YourJWTSecretKey');
        req.user = verified;
        next();  // Token valid, user object added to req
    } catch {
        return res.status(401).send('Invalid Token');
    }
});

app.use('/data', dataRoutes);

module.exports = app;
EOF
```

## ./src/routes/data_routes.js

```js
cat > ./src/routes/data_routes.js << 'EOF'
const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.json({ data: 'Secret data for admin!' });
    } else if (!req.user) {
      return res.json({ data: 'Secret data for user!' });
    } else {
      res.status(403).send('Access Denied');
    }
  } catch {
    res.status(401).send('Invalid Token');
  }
});

// Example: Role-based authorization
router.get('/users', (req, res) => {
  // Only allow access if user is authenticated and an admin
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).send('Access Denied');
  }

  // Here: retrieve and return the list of all users
  res.json({ data: 'List of all users!' });
});

// Example: Access own user data
router.get('/user', (req, res) => {
  // Only allow access if user is authenticated
  if (!req.user) {
    return res.status(403).send('Access Denied');
  }

  // Here: retrieve and return the authenticated user's own data
  res.json({ data: `Data for user with ID: ${req.user.id}` });
});


module.exports = router;
EOF
```

## Frontend server

## Instructions

```bash
#Create directory for react application
mkdir react-app && cd react-app

# Initialize a new Node.js project
npm init -y

# Install React, ReactDOM, and React Scripts
npm install react react-dom 
npm install -D react-scripts@latest

# Set up scripts in package.json
npm pkg set scripts.start="react-scripts start"
npm pkg set scripts.build="react-scripts build"
npm pkg set scripts.test="react-scripts test"
npm pkg set scripts.eject="react-scripts eject"

mkdir {src,public}
touch ./src/App.js
touch ./src/App.css
touch ./src/index.js
touch ./public/index.html
```
### ./public/index.html

```bash
cat > ./public/index.html << EOF
cat > public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>React App</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>
EOF
```

### ./src/index.js

```bash
cat > ./src/index.js << EOF
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
EOF
```

### ./src/App.js

```bash
cat > ./src/App.js << EOF
import React, { useState } from 'react';
import './App.css';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [data, setData] = useState(null);
  const [isAuthenticated, setAuthenticated] = useState(false);

  const handleLogin = async () => {
    try {
      const response = await fetch('http://localhost:3001/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!response.ok) {
        throw new Error('Login failed');
      }

      const result = await response.json();
      localStorage.setItem('access_token', result.token);
      setAuthenticated(true);
    } catch (error) {
      alert(error.message || 'Login failed!');
    }
  };

  const handleRegister = async () => {
    try {
      const response = await fetch('http://localhost:3001/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!response.ok) {
        throw new Error('Registration failed');
      }

      alert('Registration successful! You can now login.');
    } catch (error) {
      alert(error.message || 'Registration failed!');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    setAuthenticated(false);
    setData(null);
  };

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch('http://localhost:3002/data', {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!response.ok) {
        if (response.status === 401) {
          handleLogout();
          alert('Session expired. Please login again.');
          return;
        }
        throw new Error('Failed to fetch data from backend');
      }

      const result = await response.json();
      setData(result.data);
    } catch (error) {
      alert(error.message || 'Failed to fetch data');
    }
  };

  return (
      <div className="App">
        <header className="App-header">
          {isAuthenticated ?
              <>
                {data ? <p>{data}</p> : <button onClick={fetchData}>Fetch Data</button>}
                <button onClick={handleLogout}>Logout</button>
              </> :
              (<div className="auth-container">
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" className="input-field" />
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="input-field" />
                <button onClick={handleLogin} className="auth-button">Login</button>
                <button onClick={handleRegister} className="auth-button">Register</button>
              </div>)
          }
        </header>
      </div>
  );
}

export default App;
EOF
```

### ./src/App.css

```bash
cat > ./src/App.css << EOF
.App {
  text-align: center;
}

.App-logo {
  height: 40vmin;
  pointer-events: none;
}

.App-header {
  background-color: #282c34;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: calc(10px + 2vmin);
  color: white;
}

.App-link {
  color: #61dafb;
}

.login-container {
  background-color: #444;
  border-radius: 5px;
  padding: 20px;
  max-width: 300px;
  margin: 0 auto;
}

.input-field {
  width: 100%;
  padding: 10px;
  margin: 10px 0;
  font-size: 16px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.login-button {
  background-color: #61dafb;
  color: #fff;
  border: none;
  padding: 10px 20px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 16px;
}

.login-button:hover {
  background-color: #21a1f1;
}
EOF
```
