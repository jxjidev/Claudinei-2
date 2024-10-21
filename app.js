const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const PORT = 3000;

// Usuários armazenados em memória (sem criptografia de senha)
let users = [
    { username: 'admin', password: 'admin123' },
    { username: 'user', password: 'user123' }
];

app.use(bodyParser.json());
app.use(express.static('public')); // Para servir arquivos estáticos, como o HTML

// Rota de login vulnerável
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        return res.json({ message: 'Login successful' });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// Rota para obter todos os usuários (vulnerável)
app.get('/users', (req, res) => {
    res.json(users);
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
