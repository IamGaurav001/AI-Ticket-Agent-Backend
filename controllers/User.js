import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import {inngest} from '../inngest/client.js';

export const signUp = async (req, res) => {
    const {email, password, skills = []} = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({email, password: hashedPassword, skills});

        // Fire an event to Inngest
        try {
            await inngest.send({
                name: 'user/signup',
                data: {
                    email: user.email
                }
            })
        } catch (inngestError) {
            console.error('Failed to send Inngest event:', inngestError);
            // Continue with signup even if event fails
        }

        // Generate JWT token
        const token = jwt.sign({
            userId: user._id,
            email: user.email
        }, process.env.JWT_SECRET);

        return res.json({user, token})
    }
    catch (error) {
        if (error.code === 11000) {
            console.log(`Signup attempt failed: User already exists (${email})`);
            return res.status(400).json({error: 'User already exists'});
        }
        console.error('Error during sign up:', error);
        return res.status(500).json({error: 'Internal server error'});
    }
}

export const login = async (req, res) => {
    const {email, password} = req.body;
    try {
        const user = await User.findOne({email});
        if (!user) {
            return res.status(404).json({error: 'User not found'});
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({error: 'Invalid credentials'});
        }
        // Generate JWT token
        const token = jwt.sign({
            userId: user._id,   
            email: user.email   
        }, process.env.JWT_SECRET, {expiresIn: '1h'});

        return res.json({user, token});

    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({error: 'Internal server error'});
    }   
}

export const logout = async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const token = authHeader.split(' ')[1];
        jwt.verify(token, process.env.JWT_SECRET, (err) => {
            if (err) {
                return res.status(401).json({ error: 'Invalid token' });
            }
            // In stateless JWT, logout is handled on client side (by deleting token)
            return res.json({ message: 'Logged out successfully' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
} 

export const UpdateUser = async (req, res) => {
    const { skills = [], email, role } = req.body;
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const user = await User.findOne({email});
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        await User.updateOne(
            { email },
            {skills : skills.length ? skills : user.skills, role}
        );
        return res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error during user update:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

export const getUser = async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const user = await User.find().select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.json(user);
        
    } catch (error) {
        console.error('Error fetching user:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}