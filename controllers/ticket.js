import {inngest} from '../inngest/client.js';
import Ticket from '../models/ticket.js';

export const createTicket = async (req, res) => {
    try{   
        const { title, description } = req.body;

        if (!title || !description) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const newTicket = await Ticket.create({
            title,
            description,   
            createdBy: req.user._id.toString(),
        });
        await inngest.send({
            name: "ticket/created",
            data: {
                ticketId: newTicket._id.toString(),
                title,
                description,
                createdBy: req.user._id.toString(),
            },
        });
        return res.status(201).json({ message: 'Ticket created successfully', ticket: newTicket });


    }catch (err) {
        console.error('Error creating ticket:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

export const getTickets = async (req, res) => {
    try {
        const user = req.user;
        let tickets = [];
        if (user.role !== 'user') {
            tickets = await Ticket.find({})
            .populate("assignedTo", ["email", "_id"])
            .sort({ createdAt: -1 });
        }else{
            tickets = await Ticket.find({ createdBy: user._id })
            .select("title description status createdAt")
            .sort({ createdAt: -1 });
        }
        return res.status(200).json({ tickets });
    }catch (err) {
        console.error('Error fetching tickets:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

export const getTicket = async (req, res) => {
    try {
        const user = req.user; 
        let ticket;
        if (user.role !== 'user') {
            ticket = await Ticket.findById(req.params.id)
                .populate("assignedTo", ["email", "_id"]);
        } else {
            ticket = await Ticket.findOne({ _id: req.params.id, createdBy: user._id })
                .select("title description status createdAt");
        }
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        return res.status(200).json({ ticket });
    } catch (err) {
        console.error('Error fetching ticket:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

