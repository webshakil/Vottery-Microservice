import express from 'express';
import { registerKeys, addSecurityQuestion, getSecurityQuestions, verifySecurityAnswers } from '../controllers/biometricFallbackController.js';

const router = express.Router();

// Register keys for a user
router.post('/register-keys/:userId', async (req, res) => {
  try {
    const result = await registerKeys(req.params.userId);
    res.json({ success: true, keys: result });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Add security question
router.post('/add-question/:userId', express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { question, answer } = req.body;
    const result = await addSecurityQuestion(req.params.userId, question, answer);
    res.json({ success: true, question: result });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Get security questions
router.get('/questions/:userId', async (req, res) => {
  try {
    const questions = await getSecurityQuestions(req.params.userId);
    res.json({ success: true, questions });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Verify answers
router.post('/verify/:userId', express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { answers } = req.body;
    await verifySecurityAnswers(req.params.userId, answers);
    res.json({ success: true, message: 'All answers verified' });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

export default router;
