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
npm install express express-validator cors body-parser bcrypt jsonwebtoken dotenv
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
app.use(passport.initialize());

// Routes
app.use('/auth', authRoutes);

module.exports = app;
EOF
```

### ./src/auth/passport_config.js

```js
cat > ./src/auth/passport_config.js << 'EOF'
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

// Example User Model
const users = [
  { id: 1, email: 'user@example.com', password: 'hashedpassword', role: 'user' } // Replace hashedpassword with an actual hashed password
];

passport.use(new LocalStrategy(
  { usernameField: 'email' },
  (email, password, done) => {
    const user = users.find(u => u.email === email);
    if (!user) return done(null, false, { message: 'User not found' });
    
    const isValid = bcrypt.compareSync(password, user.password);
    return isValid ? done(null, user) : done(null, false, { message: 'Incorrect Password' });
  }
));

EOF
```

## ./src/routes/auth_routes.js

```js
cat > ./src/routes/auth_routes.js << 'EOF'
const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { check, validationResult } = require('express-validator');

const router = express.Router();

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

module.exports = router;
EOF
```

## Test it 

```bash
# Command line URL
# -c --cookie-jar
# -b --cookie
# -d urlencoded data

# Log in and save cookies to a file
curl -X POST -c cookies.txt -d "username=user@example.com&password=password" http://localhost:3001/login

# Attempt access to protected resource
curl -X GET http://localhost:3001/protected

# Use the saved cookies in subsequent requests
curl -X GET -b cookies.txt http://localhost:3001/protected

curl -X POST http://localhost:3001/logout \
     -b cookies.txt \
     -c cookies.txt

# Use the saved cookies in subsequent requests
curl -X GET -b cookies.txt http://localhost:3001/protected

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

## jest

```
```






> Ensure to hash your passwords when they’re stored, and only store the hashed versions. bcrypt can be used to hash passwords before they are saved to your database.
Always secure your application by moving sensitive information like secret keys or database credentials to environment variables and never expose them in the code.
Ensure thorough testing, especially for authentication functionalities, to make sure that security is not compromised.
Ensure your application uses HTTPS to securely transmit data, especially credentials, between client and server.
