import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json()); 


app.use(helmet());


const corsOptions = {
    origin: 'http://example.com', 
    methods: 'GET, POST',
};
app.use(cors(corsOptions));


const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 5, 
    message: 'Trop de requêtes, veuillez réessayer plus tard.',
});
app.use(limiter);


const API_KEY = '12345-ABCDE';


const checkApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key']; 
    if (!apiKey || apiKey !== API_KEY) {
        return res.status(403).json({ message: 'Accès refusé : clé API invalide ou manquante.' });
    }
    next(); 
};


const users = [
    { email: 'baradjiassa@.gmail.com', password: 'password123' }, 
];


app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Identifiants invalides.' });
    }

  
    const token = jwt.sign({ email: user.email }, 'votre_secret_jwt', { expiresIn: '1h' }); 
    res.json({ token });
});


const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; 
    if (!token) {
        return res.status(401).json({ message: 'Accès non autorisé : token manquant.' });
    }

    jwt.verify(token, 'votre_secret_jwt', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Accès non autorisé : token invalide.' });
        }
        req.user = decoded; 
        next(); 
    });
};


app.get('/api/new-private-data', verifyToken, (req, res) => {
    res.json({ message: 'Voici les nouvelles données privées.' });
});


const PORT = process.env.PORT || 3005;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
