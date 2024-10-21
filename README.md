# V-lneravel-

Vulnerabilidades do Código
Armazenamento de Senhas em Texto Plano

javascript
Copiar código
let users = [
    { id: 1, username: 'admin', password: 'admin123', email: 'admin@example.com' },
    { id: 2, username: 'user', password: 'user123', email: 'user@example.com' }
];
Vulnerabilidade: As senhas dos usuários estão armazenadas em texto plano, o que significa que qualquer pessoa com acesso ao banco de dados pode vê-las diretamente.

Melhoria: Use uma biblioteca como bcrypt para hash e salgar as senhas antes de armazená-las.

Tipo de ataque: Roubo de credenciais. Um invasor que tenha acesso ao banco de dados pode ver todas as senhas diretamente.

Login Sem Validação Rigorosa

javascript
Copiar código
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
        return res.json({ message: 'Login successful', token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});
Vulnerabilidade: O login aceita qualquer combinação de username e password, sem limites de tentativas, o que facilita ataques de força bruta.

Melhoria: Implemente um sistema de bloqueio após várias tentativas de login falhadas e utilize um limite de taxa.

Tipo de ataque: Ataque de força bruta. Um invasor pode tentar múltiplas combinações de credenciais rapidamente.

JWT Sem Expiração

javascript
Copiar código
const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
Vulnerabilidade: O token JWT gerado não tem uma data de expiração, o que significa que, uma vez que um token é emitido, ele é válido indefinidamente.

Melhoria: Adicione um tempo de expiração ao token JWT para reduzir a janela de tempo em que um token comprometido pode ser usado.

Tipo de ataque: Roubo de token. Um invasor que consiga capturar o token pode usá-lo indefinidamente.

Falta de Controle de Acesso

javascript
Copiar código
app.get('/users', authenticateJWT, (req, res) => {
    res.json(users);
});
Vulnerabilidade: Qualquer usuário autenticado pode acessar todos os usuários. Não há distinção entre papéis (admin, usuário comum).

Melhoria: Implemente controle de acesso baseado em papéis (RBAC) para garantir que apenas usuários autorizados possam acessar dados sensíveis.

Tipo de ataque: Exposição de dados. Um usuário comum poderia acessar informações sensíveis sobre outros usuários.

Falha em Filtrar Dados de Entrada

javascript
Copiar código
app.post('/users', authenticateJWT, (req, res) => {
    const { username, password, email } = req.body;
    const newUser = { id: users.length + 1, username, password, email };
    users.push(newUser);
    res.status(201).json(newUser);
});
Vulnerabilidade: Não há validação de entrada. Um usuário pode tentar criar um usuário com um formato inválido ou injetar dados maliciosos.

Melhoria: Valide todos os dados de entrada usando uma biblioteca como Joi ou express-validator para evitar injeção de código e garantir que os dados sejam válidos.

Tipo de ataque: Injeção de SQL (se um banco de dados real for usado) ou Injeção de Dados. Dados maliciosos podem comprometer a integridade do sistema.

Exemplos de Invasões Possíveis
Roubo de Credenciais: Como mencionado, armazenar senhas em texto plano permite que um invasor acesse diretamente as credenciais dos usuários.
Ataques de Força Bruta: Um invasor pode automatizar tentativas de login com diferentes combinações de usuário e senha.
Captura de Token: Um token JWT que não expira pode ser capturado em uma requisição insegura (como HTTP em vez de HTTPS) e usado para acessar a aplicação indefinidamente.
Acesso Não Autorizado a Dados Sensíveis: Um usuário comum pode acessar dados de outros usuários se não houver controle de acesso adequado.


O código apresentado é intencionalmente vulnerável para fins educacionais, destacando a importância de implementar boas práticas de segurança em qualquer aplicação. Sempre que você desenvolver uma aplicação, considere os seguintes princípios de segurança:

Armazenar Senhas com Segurança: Sempre utilize hash e sal para senhas.
Validar Entrada do Usuário: Nunca confie nos dados enviados pelo cliente.
Implementar Controle de Acesso: Restringir o acesso a dados sensíveis com base em permissões.
Usar HTTPS: Sempre proteja a comunicação entre o cliente e o servidor.
Rotinas de Limitação de Taxa: Implemente mecanismos para prevenir ataques de força bruta.
Essas práticas ajudarão a proteger a aplicação contra as ameaças mais comuns e garantir a segurança dos dados dos usuários.


O que você precisa
Node.js e npm: Verifique se você tem o Node.js instalado. Você pode baixar em nodejs.org.
Editor de Código: Use um editor como Visual Studio Code.
Postman: Uma ferramenta para testar APIs. Baixe em postman.com.
Passo a Passo
1. Criar o Projeto
Crie um diretório para o seu projeto:

bash
Copiar código
mkdir vulneravel-app
cd vulneravel-app
Inicialize um novo projeto Node.js:

bash
Copiar código
npm init -y
Instale as dependências necessárias:

bash
Copiar código
npm install express body-parser jsonwebtoken
2. Criar o Código da Aplicação
Crie um arquivo chamado app.js e adicione o seguinte código:

javascript
Copiar código
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Usuários armazenados em memória (sem criptografia de senha)
let users = [
    { id: 1, username: 'admin', password: 'admin123', email: 'admin@example.com' },
    { id: 2, username: 'user', password: 'user123', email: 'user@example.com' }
];

// Segredo fraco para os tokens JWT
const JWT_SECRET = 'myweaksecret';

// Middleware para verificar tokens JWT
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token not provided' });
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

app.use(bodyParser.json());

// Rota de login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
        return res.json({ message: 'Login successful', token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// Rota para criar um novo usuário
app.post('/users', authenticateJWT, (req, res) => {
    const { username, password, email } = req.body;
    const newUser = { id: users.length + 1, username, password, email };
    users.push(newUser);
    res.status(201).json(newUser);
});

// Rota para obter todos os usuários
app.get('/users', authenticateJWT, (req, res) => {
    res.json(users);
});

// Rota para atualizar um usuário
app.put('/users/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { username, password, email } = req.body;
    const user = users.find(u => u.id == id);
    if (user) {
        user.username = username;
        user.password = password;
        user.email = email;
        return res.json(user);
    }
    res.status(404).json({ message: 'User not found' });
});

// Rota para deletar um usuário
app.delete('/users/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    users = users.filter(u => u.id != id);
    res.status(204).send();
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
3. Executar a Aplicação
No terminal, execute o seguinte comando para iniciar o servidor:
bash
Copiar código
node app.js
4. Testar a Aplicação com Postman
Agora, você pode usar o Postman para testar a aplicação.

Login:

Método: POST
URL: http://localhost:3000/login
Corpo (Body):
json
Copiar código
{
    "username": "admin",
    "password": "admin123"
}
Resposta Esperada:
json
Copiar código
{
    "message": "Login successful",
    "token": "<seu_token_jwt_aqui>"
}
Criar um novo usuário (use o token recebido):

Método: POST
URL: http://localhost:3000/users
Cabeçalhos (Headers):
Authorization: Bearer <seu_token_jwt_aqui>
Corpo (Body):
json
Copiar código
{
    "username": "newuser",
    "password": "newpassword",
    "email": "newuser@example.com"
}
Resposta Esperada:
json
Copiar código
{
    "id": 3,
    "username": "newuser",
    "password": "newpassword",
    "email": "newuser@example.com"
}
Obter todos os usuários (use o token recebido):

Método: GET
URL: http://localhost:3000/users
Cabeçalhos (Headers):
Authorization: Bearer <seu_token_jwt_aqui}
Resposta Esperada:
json
Copiar código
[
    { "id": 1, "username": "admin", "password": "admin123", "email": "admin@example.com" },
    { "id": 2, "username": "user", "password": "user123", "email": "user@example.com" },
    { "id": 3, "username": "newuser", "password": "newpassword", "email": "newuser@example.com" }
]
Considerações de Segurança
A aplicação é intencionalmente vulnerável. Aqui estão algumas melhorias que poderiam ser feitas:

Criptografia de Senha: As senhas devem ser armazenadas de forma criptografada, utilizando bibliotecas como bcrypt.
Validação de Entrada: Validar todos os dados recebidos nas requisições para evitar injeções de SQL ou outros tipos de ataques.
Controle de Acesso: Implementar um controle de acesso mais robusto para garantir que os usuários só possam acessar e modificar suas próprias informações.
Token de Expiração: O token JWT deve ter uma data de expiração para reduzir o risco de um token sendo usado indevidamente após o login.
