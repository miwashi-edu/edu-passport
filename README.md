# edu-web-security-passport

## Instructions

```bash
cd auth-server
npm install mongoose
touch ./src/db.js
```

## Auth Servder

### ./src/db.js

```js
cat > ./src/db.js << 'EOF'
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/yourDBName', {useNewUrlParser: true, useUnifiedTopology: true})
    .then(() => console.log('Connected to MongoDB...'))
    .catch(err => console.error('Could not connect to MongoDB...', err));
EOF
```

### ./src/models/User.js

```
cat > ./src/models/User.js << 'EOF'
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    role: {type: String, required: true},
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOF
```


### ./src/routes/auth_routes.js

```js
const express = require('express');
const bcrypt = require('bcrypt');
const User = require('./models/User');  // Importing User model
const router = express.Router();

#...

router.post('/register', async (req, res) => {
    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Create new user
        const user = new User({
            email: req.body.email,
            password: hashedPassword,
            role: req.body.role || 'user',
        });

        // Save user in MongoDB
        const savedUser = await user.save();

        // Send appropriate response
        res.status(201).json({ message: "User registered", userId: savedUser._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

#...

router.post('/login', async (req, res) => {
    // Retrieve user from database
    const user = await User.findOne({ email: req.body.email });

    // Check if user exists and password is correct
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        // User authentication logic here (e.g., create JWT)
        ...
    } else {
        res.status(401).json({ message: 'Authentication failed' });
    }
});

```
