import express from 'express';
import { getUser, signUp, login, logout, UpdateUser } from '../controllers/User.js';
import { authenticate } from '../middlewares/auth.js';

const router = express.Router();

router.post('/update-user', authenticate, UpdateUser );
router.get('/get-user', authenticate, getUser);

router.post('/signup', signUp);
router.post('/login', login);
router.post('/logout', logout);

export default router;